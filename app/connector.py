import logging as log
import os
import time
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from app.lib.CarbonBlack import CarbonBlack
from app.lib.VMRay import VMRay
from app.config.conf import CarbonBlackConfig, GeneralConfig, RUNTIME_MODE


def run():
    if not GeneralConfig.LOG_DIR.exists():
        GeneralConfig.LOG_DIR.mkdir()

    if not GeneralConfig.LOG_FILE_PATH.exists():
        GeneralConfig.LOG_FILE_PATH.touch()

    if not CarbonBlackConfig.DOWNLOAD_DIR_PATH.exists():
        CarbonBlackConfig.DOWNLOAD_DIR_PATH.mkdir()

    # Configure logging
    log.basicConfig(filename=GeneralConfig.LOG_FILE_PATH,
                    format='[%(asctime)s] <pid:%(process)d> %(levelname)s %(message)s', level=GeneralConfig.LOG_LEVEL)
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

    # Retrieving enriched events from CarbonBlack
    enriched_events = cb.get_enriched_events()

    # Extracting sha256 hash values from enriched events
    hash_list.update(cb.extract_hash_from_enriched_events(enriched_events))

    # Retrieving alerts from CarbonBlack
    alerts = cb.get_alerts()

    # Extracting sha256 hash values from alerts
    hash_list.update(cb.extract_hash_from_alerts(alerts))

    # Checking hash values in VMRay database, if sample found on VMRay no need to submit again
    for sha256 in hash_list:
        sample = vmray.get_sample(sha256)
        if sample is not None:
            found_samples.append({"sha256": sha256, "is_truncated": False, "sample": sample})
        else:
            download_samples.append({"sha256": sha256, "is_truncated": False, "sample": sample})

    log.info("%d samples found on VMRay database" % len(found_samples))
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
                log.info(
                    "Truncated file %s found on VMRay database. Not need to submit again." % file["truncated_sha256"])
                found_samples.append(
                    {"sha256": file["sha256"], "truncated_sha256": file["truncated_sha256"], "is_truncated": True,
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
                ioc_data["sha256"].append(sample["sha256"])

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

    # Removing downloaded files
    for file in files:
        os.remove(file["path"])


if __name__ == "__main__":
    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info("Sleeping %d seconds." % GeneralConfig.TIME_SPAN)
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
