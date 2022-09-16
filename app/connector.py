import logging as log
import os
import time
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from app.lib.CarbonBlack import CarbonBlack
from app.lib.VMRay import VMRay
from app.config.conf import CarbonBlackConfig, VMRayConfig, GeneralConfig, RUNTIME_MODE, DATA_SOURCE


def run():
    if not GeneralConfig.LOG_DIR.exists():
        GeneralConfig.LOG_DIR.mkdir()

    if not GeneralConfig.LOG_FILE_PATH.exists():
        GeneralConfig.LOG_FILE_PATH.touch()

    if not CarbonBlackConfig.DOWNLOAD_DIR_PATH.exists():
        CarbonBlackConfig.DOWNLOAD_DIR_PATH.mkdir()

    # Configure logging
    log.basicConfig(filename=GeneralConfig.LOG_FILE_PATH,
                    format='[%(asctime)s] [<pid:%(process)d> %(filename)s:%(lineno)s %(funcName)s] %(levelname)s %(message)s',
                    level=GeneralConfig.LOG_LEVEL)
    log.info('[CONNECTOR.PY] Started VMRAY Analyzer Connector for VMware Carbon Black Cloud')

    # Initializing and authenticating api instances
    cb = CarbonBlack(log)
    vmray = VMRay(log)

    # Creating set object for sha256 hash values
    hash_list = set()

    # List of samples which found on VMRay database
    found_samples = []

    # List of samples which need to be downloaded from CarbonBlack
    download_samples = []

    # List of samples which found on VMRay database but will be resubmitted
    resubmit_samples = []

    if DATA_SOURCE.PROCESS in CarbonBlackConfig.SELECTED_DATA_SOURCES:
        # Retrieving processes from CarbonBlack
        processes = cb.get_processes()

        # Extracting sha256 hash values from processes
        hash_list.update(cb.extract_hash_from_processes(processes))

    if DATA_SOURCE.ENRICHED_EVENTS in CarbonBlackConfig.SELECTED_DATA_SOURCES:
        # Retrieving enriched events from CarbonBlack
        enriched_events = cb.get_enriched_events()

        # Extracting sha256 hash values from enriched events
        hash_list.update(cb.extract_hash_from_enriched_events(enriched_events))

    if DATA_SOURCE.ALERTS in CarbonBlackConfig.SELECTED_DATA_SOURCES:
        # Retrieving alerts from CarbonBlack
        alerts = cb.get_alerts()

        # Extracting sha256 hash values from alerts
        hash_list.update(cb.extract_hash_from_alerts(alerts))

    # Checking found hashes on Carbon Black, if no hash has been found no need to proceed
    if len(hash_list) == 0:
        if len(CarbonBlackConfig.SELECTED_DATA_SOURCES) > 0:
            log.warning("No evidence hash was found on Carbon Black. Selected data sources: %s" % ",".join(
                CarbonBlackConfig.SELECTED_DATA_SOURCES))
        else:
            log.warning("No data source was selected and no evidence hash was found on Carbon Black")
        return

    try:
        # Checking hash values in VMRay database
        for sha256 in hash_list:
            sample = vmray.get_sample(sha256)
            if sample is not None:
                # If resubmission is active and sample verdicts in configured resubmission verdicts
                # Hash added into resubmit samples and re-analyzed
                sample_metadata = vmray.parse_sample_data(sample)

                if VMRayConfig.RESUBMIT and sample_metadata["sample_verdict"] in VMRayConfig.RESUBMISSION_VERDICTS:
                    log.debug(
                        "File %s found in VMRay database, but will be resubmitted." % sha256)
                    resubmit_samples.append({"sha256": sha256, "is_truncated": False, "sample": sample})
                else:
                    log.debug(
                        "File %s found in VMRay database. No need to submit again." % sha256)
                    found_samples.append({"sha256": sha256, "is_truncated": False, "sample": sample})
            else:
                download_samples.append({"sha256": sha256, "is_truncated": False, "sample": sample})

        if len(found_samples) > 0:
            log.info("%d samples found on VMRay database" % len(found_samples))

        if len(resubmit_samples) > 0:
            log.info("%d samples found on VMRay database, but will be resubmitted" % len(resubmit_samples))

        # Combine download_samples array and resubmit_samples array for submission
        download_samples.extend(resubmit_samples)

        if len(download_samples) > 0:
            log.info("%d samples need to be downloaded and submitted" % len(download_samples))

        # Retrieving watchlists from CarbonBlack
        watchlists = cb.get_watchlists()

        # Retrieving feeds from CarbonBlack
        feeds = cb.get_feeds()

        # Extracting IOC values from watchlists and feeds to check duplicate IOC values
        old_iocs = cb.get_iocs(watchlists, feeds)

        # Retrieving connector watchlist
        watchlist = cb.get_watchlist()

        # If watchlist is not found, creating connector watchlist
        if watchlist is None:
            watchlist = cb.create_watchlist()

        # Retrieving binary information to download samples from CarbonBlack UBS
        binary_list = cb.get_ubs_binaries(download_samples)

        # Downloading binaries from CarbonBlack UBS
        files = cb.download_ubs_binaries(binary_list)

        # Second check for files which bigger than 25MB and truncated by Carbon Black
        for file in files:
            if file["is_truncated"]:
                sample = vmray.get_sample(file["truncated_sha256"])
                if sample is not None:
                    sample_metadata = vmray.parse_sample_data(sample)

                    if VMRayConfig.RESUBMIT and sample_metadata["sample_verdict"] in VMRayConfig.RESUBMISSION_VERDICTS:
                        log.debug(
                            "Truncated file %s found on VMRay database, but will be resubmitted." %
                            file["truncated_sha256"])
                    else:
                        log.debug(
                            "Truncated file %s found on VMRay database. No need to submit again." %
                            file["truncated_sha256"])
                        found_samples.append(
                            {"sha256": file["sha256"], "truncated_sha256": file["truncated_sha256"],
                             "is_truncated": True,
                             "sample": sample})
                        file["is_processed"] = True

        # Extracting reports and IOC values from VMRay for found samples
        for sample in found_samples:
            sample_data = vmray.parse_sample_data(sample["sample"])

            # If sample identified as suspicious or malicious we need to extract IOC values and import them to CarbonBlack
            if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
                sample_iocs = vmray.get_sample_iocs(sample_data)
                ioc_data = vmray.parse_sample_iocs(sample_iocs)

                ioc_data["sha256"].add(sample_data["sample_sha256hash"])

                if sample["is_truncated"]:
                    ioc_data["sha256"].add(sample["sha256"])

                # Creating CarbonBlack IOCV2 objects for IOC values
                iocv2_objects = cb.create_iocv2_objects(ioc_data, sample_data, old_iocs)

                # Creating watchlist reports for new IOC values
                if len(iocv2_objects) > 0:
                    vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                    sample_vtis = vmray.parse_sample_vtis(vti_data)
                    cb.create_report(watchlist, iocv2_objects, sample_data, sample_vtis)

                    # Banning sample sha256 with Carbon Black Reputation Black List
                    if cb.config.AUTO_BAN:
                        if sample_data["sample_verdict"] in cb.config.AUTO_BAN_VERDICTS:
                            cb.auto_ban_sample(sample["sha256"])

        # Submitting downloaded samples to VMRay
        submissions = vmray.submit_samples(files)

        # Waiting and processing submissions
        for result in vmray.wait_submissions(submissions):
            submission = result["submission"]
            vmray.check_submission_error(submission)

            if result["finished"]:
                sample = vmray.get_sample(submission["sample_id"], True)
                sample_data = vmray.parse_sample_data(sample)

                # If sample identified as suspicious or malicious we need to extract IOC values and import them to CarbonBlack
                if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
                    sample_iocs = vmray.get_sample_iocs(sample_data)
                    ioc_data = vmray.parse_sample_iocs(sample_iocs)

                    ioc_data["sha256"].add(sample_data["sample_sha256hash"])

                    if submission["is_truncated"]:
                        ioc_data["sha256"].add(submission["sha256"])

                    # Creating CarbonBlack IOCV2 objects for IOC values
                    iocv2_objects = cb.create_iocv2_objects(ioc_data, sample_data, old_iocs)

                    # Creating watchlist reports for new IOC values
                    if len(iocv2_objects) > 0:
                        vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                        sample_vtis = vmray.parse_sample_vtis(vti_data)
                        cb.create_report(watchlist, iocv2_objects, sample_data, sample_vtis)

                        # Banning sample sha256 with Carbon Black Reputation Black List
                        if cb.config.AUTO_BAN:
                            if sample_data["sample_verdict"] in cb.config.AUTO_BAN_VERDICTS:
                                cb.auto_ban_sample(submission["sha256"])

                        # Quarantine devices which running malicious process
                        if cb.config.QUARANTINE:
                            if sample_data["sample_verdict"] in cb.config.QUARANTINE_VERDICTS:
                                device_ids = cb.get_device_ids(submission["sha256"])
                                cb.quarantine_devices(device_ids)

        # Removing downloaded files
        for file in files:
            os.remove(file["path"])

    except Exception as err:
        log.error("Unknown error occurred. Error %s" % str(err))


if __name__ == "__main__":
    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info("Sleeping %d seconds." % GeneralConfig.TIME_SPAN)
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
