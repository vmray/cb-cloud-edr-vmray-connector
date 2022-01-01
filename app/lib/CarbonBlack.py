import requests
import pathlib
import zipfile
import os
import math
import hashlib
from datetime import datetime, timedelta

from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import BaseAlert, ReputationOverride, Process
from cbc_sdk.endpoint_standard import EnrichedEvent
from cbc_sdk.enterprise_edr.ubs import Binary
from cbc_sdk.enterprise_edr import Watchlist, Report, IOC_V2, Feed

from app.config.conf import CarbonBlackConfig, IOC_FIELD_MAPPINGS, VERDICT


def clean_string(string):
    """
    Clean starting and trailing quotation marks in IOC values
    :param string: string to clean
    :return ioc: cleaned IOC string
    """
    ioc = str(string).strip()
    if ioc.startswith("\"") or ioc.startswith("'"):
        ioc = ioc[1:]
    if ioc.endswith("\"") or ioc.endswith("'"):
        ioc = ioc[:-1]
    return ioc


class CarbonBlack:
    """
        Wrapper class for Carbon Black Cloud SDK modules.
        Import this class to retrieve alerts, events, enriched events and extract SHA256 hashes.
    """

    def __init__(self, log):
        """
        Initialize and authenticate the CarbonBlack instance, use CarbonBlackConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.config = CarbonBlackConfig
        self.log = log

        self.authenticate()

    def authenticate(self):
        """
        Authenticate the CBC SDK with cbc-config.cbc configuration file for configured profile
        :raise: CredentialError when credentials are not properly configured
        :return: void
        """
        try:
            self.api = CBCloudAPI(credential_file=self.config.CONFIG_FILE_PATH, profile=self.config.PROFILE)
            self.log.debug("Successfully authenticated the CBC API with %s" % self.config.CONFIG_FILE_PATH)
        except Exception as err:
            self.log.error(err)
            raise

    def get_processes(self):
        """
        Retrieve processes with configured timespan
        :exception: when processes are not properly retrieved
        :return processes: list of process objects
        """
        processes = []
        start_time = (datetime.now() - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        # AsyncQueries doesn't support the set_create_time function
        # Therefore, we need to use a raw query for filtering with the timespan
        timespan_filter_query = "(process_start_time:[%s TO %s])" % (start_time, end_time)

        if self.config.EXCLUSION_QUERY is not None:
            filter_query = self.config.EXCLUSION_QUERY
            filter_query += " AND " + timespan_filter_query

            # With the set_fields function, only necessary attributes are retrieved from Carbon Black.
            query = self.api.select(Process). \
                where(filter_query). \
                set_fields(["process_hash", "process_guid"])
        else:
            query = self.api.select(Process). \
                where(timespan_filter_query). \
                set_fields(["process_hash", "process_guid"])

        try:
            processes = list(query)
            self.log.info("Successfully retrieved %d processes" % len(processes))
        except Exception as err:
            self.log.error(err)
        return processes

    def get_alerts(self):
        """
        Retrieve alerts with configured timespan
        :exception: when alerts are not properly retrieved
        :return alerts: list of alerts
        """
        alerts = []
        start_time = (datetime.now() - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        if self.config.EXCLUSION_QUERY is not None:
            query = self.api.select(BaseAlert). \
                where(self.config.EXCLUSION_QUERY). \
                set_create_time(start=start_time, end=end_time)
        else:
            query = self.api.select(BaseAlert). \
                set_create_time(start=start_time, end=end_time)
        try:
            alerts = list(query)
            self.log.info("Successfully retrieved %d alerts" % len(alerts))
        except Exception as err:
            self.log.error(err)
        return alerts

    def get_enriched_events(self):
        """
        Retrieve enriched events with configured timespan
        :exception: when enriched events are not properly retrieved
        :return enriched_events: list of enriched events
        """
        enriched_events = []
        start_time = (datetime.now() - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        if self.config.EXCLUSION_QUERY is not None:
            query = self.api.select(EnrichedEvent). \
                where(self.config.EXCLUSION_QUERY). \
                set_time_range(start=start_time, end=end_time). \
                set_rows(self.config.MAX_ENRICHED_EVENT_COUNT)
        else:
            query = self.api.select(EnrichedEvent). \
                where(enriched=True). \
                set_time_range(start=start_time, end=end_time). \
                set_rows(self.config.MAX_ENRICHED_EVENT_COUNT)
        try:
            enriched_events = list(query)
            self.log.info("Successfully retrieved %d enriched events" % len(enriched_events))
        except Exception as err:
            self.log.error(err)
        return enriched_events

    def get_ubs_binaries(self, download_samples):
        """
        Retrieve binaries with given SHA256 hash list
        :exception when given SHA256 hash not found in Unified Binary Store
        :param download_samples: list of samples which found in enriched events and alerts
        :return binaries: list of binary dicts (contains binary download url and hash value)
        """
        binaries = []
        for sample in download_samples:
            try:
                binary_object = self.api.select(Binary, sample["sha256"])
                download_url = binary_object.download_url()
                if download_url is not None:
                    binaries.append({"url": download_url, "sha256": sample["sha256"]})
                else:
                    self.log.error("Failed to create download url for %s" % sample["sha256"])
            except Exception as err:
                self.log.error("%s - %s" % (str(err), sample["sha256"]))
        self.log.info("Successfully retrieved %d binary from Unified Binary Store" % len(binaries))
        return binaries

    def download_ubs_binaries(self, binary_list):
        """
        Download and extract binaries from Unified Binary Store with given binary list
        :param binary_list: list of binary dicts (contains binary download url and hash value)
        :return files: list of file paths for successfully downloaded binaries
        """
        files = []
        for binary in binary_list:
            try:
                response = requests.get(binary["url"], stream=True)
                file_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(binary["sha256"] + ".zip")
                unzipped_file_path = self.config.DOWNLOAD_DIR_PATH / pathlib.Path(binary["sha256"])
                self.log.debug(
                    "File %s downloaded successfully. Response code: %d" % (binary["sha256"], response.status_code))
                try:
                    with open(file_path, "wb") as file:
                        for chunk in response.iter_content(1024):
                            if chunk:
                                file.write(chunk)
                    self.log.debug("File %s saved successfully" % binary["sha256"])
                    try:
                        with zipfile.ZipFile(file_path, "r") as zip_ref:
                            zip_info = zip_ref.getinfo("filedata")
                            zip_info.filename = binary["sha256"]
                            zip_ref.extract(zip_info, self.config.DOWNLOAD_DIR_PATH)
                        path_dict = {"path": unzipped_file_path, "sha256": binary["sha256"], "is_truncated": False,
                                     "is_processed": False, "truncated_sha256": None}
                        os.remove(file_path)
                        self.log.debug("File %s extracted successfully" % binary["sha256"])
                        try:
                            # Calculate SHA256 hash values for downloaded/extracted files
                            # Because Carbon Black only collect first 25MB of files, so hash value may be different
                            sha256_hash = hashlib.sha256()
                            with open(unzipped_file_path, "rb") as file:
                                for byte_block in iter(lambda: file.read(4096), b""):
                                    sha256_hash.update(byte_block)
                            self.log.debug("SHA256 for %s calculated successfully" % binary["sha256"])
                            if str(sha256_hash.hexdigest()).lower() != binary["sha256"].lower():
                                path_dict["truncated_sha256"] = sha256_hash.hexdigest()
                                path_dict["is_truncated"] = True
                            files.append(path_dict)
                        except Exception as err:
                            self.log.error("SHA256 calculation error for %s. Err: %s " % (binary["sha256"], str(err)))
                    except Exception as err:
                        self.log.error("Failed to unzip %s - Error: %s" % (binary["sha256"], err))
                except Exception as err:
                    self.log.error("Failed to write %s to %s - Error: %s" % (binary["sha256"], file_path, err))
            except Exception as err:
                self.log.error("Failed to download %s - Error: %s" % (binary["sha256"], err))
        self.log.info("Successfully downloaded %d binaries from Unified Binary Store" % len(files))
        return files

    def extract_hash_from_processes(self, processes):
        """
        Extract SHA256 hash of process binaries from given process objects
        :param processes: list of processes
        :return: hashes: list of SHA256 hashes
        """
        hashes = set()
        for process in processes:
            try:
                # process_hash is list object which contains MD5 and SHA256 hash values
                for hash_value in process.process_hash:
                    # Filtering only SHA256 hash values with length check
                    if hash_value is not None and len(hash_value) == 64:
                        hashes.add(hash_value)
            except Exception:
                # Some process object doesn't contain process_hash attribute, we need to skip them.
                pass
        self.log.info("%d unique SHA256 hash retrieved from %d processes" % (len(hashes), len(processes)))
        return hashes

    def extract_hash_from_alerts(self, alerts):
        """
        Extract SHA256 hash of process binaries from given alerts
        :param alerts: list of alerts
        :return hashes: list of SHA256 hashes
        """
        hashes = set()
        for alert in alerts:
            if hasattr(alert, "original_document"):
                document = alert.original_document
                if document is not None:
                    if "threat_cause_actor_sha256" in document:
                        if document["threat_cause_actor_sha256"] is not None:
                            hashes.add(document["threat_cause_actor_sha256"])
        self.log.info("%d unique SHA256 hash retrieved from %d alerts" % (len(hashes), len(alerts)))
        return list(hashes)

    def extract_hash_from_enriched_events(self, enriched_events):
        """
        Extract SHA256 hash of process binaries from given enriched events
        :param enriched_events: list of enriched events
        :return: hashes: list of SHA256 hashes
        """
        hashes = set()
        for event in enriched_events:
            if hasattr(event, "process_sha256"):
                if event.process_sha256 is not None:
                    hashes.add(event.process_sha256)
        self.log.info("%d unique SHA256 hash retrieved from %d enriched events" % (len(hashes), len(enriched_events)))
        return list(hashes)

    def get_watchlists(self):
        """
        Retrieve watchlist objects for duplicate IOC lookups
        :exception when watchlist objects are not properly retrieved
        :return watchlists: list of watchlist objects
        """
        watchlists = []
        query = self.api.select(Watchlist)
        try:
            watchlists = list(query)
            self.log.info("Successfully retrieved %d watchlists" % len(watchlists))
        except Exception as err:
            self.log.error(err)
        return watchlists

    def get_feeds(self):
        """
        Retrieve feed objects for duplicate IOC lookups
        :exception when feed objects are not properly retrieved
        :return feeds: list of feed objects
        """
        feeds = []
        query = self.api.select(Feed)
        try:
            feeds = list(query)
            self.log.info("Successfully retrieved %d feeds" % len(feeds))
        except Exception as err:
            self.log.error(err)
        return feeds

    def get_iocs(self, watchlists, feeds):
        """
        Extract equality IOC objects/values from watchlists and feeds for duplicate IOC lookups
        :param watchlists: list of watchlist objects
        :param feeds: list of feed objects
        :return iocs: list of IOC values like IP, Domain, SHA256 etc
        """
        iocs = []

        for watchlist in watchlists:
            try:
                for report in watchlist.reports:
                    try:
                        for ioc_v2 in report.iocs_v2:
                            if ioc_v2["match_type"] == "equality":
                                iocs.extend(ioc_v2["values"])
                    except Exception as err:
                        self.log.error(
                            "Watchlist (%s) report IOC error: %s" % (watchlist.original_document["name"], str(err)))
            except Exception as err:
                self.log.error("Watchlist (%s) report error: %s" % (watchlist.original_document["name"], str(err)))

        for feed in feeds:
            try:
                for report in feed.reports:
                    try:
                        for ioc_v2 in report.iocs_v2:
                            if ioc_v2["match_type"] == "equality":
                                iocs.extend(ioc_v2["values"])
                    except Exception as err:
                        self.log.error("Feed (%s) report IOC error: %s" % (feed.original_document["name"], str(err)))
            except Exception as err:
                self.log.error("Feed (%s) report error: %s" % (feed.original_document["name"], str(err)))

        self.log.info("%d IOC value found in watchlists and feeds." % len(iocs))
        return iocs

    def get_watchlist(self):
        """
        Retrieve all watchlists and filter connector watchlist by name
        :return watchlist: watchlist object for connector if found
        """
        watchlists = []
        query = self.api.select(Watchlist)

        try:
            watchlists = list(query)
            self.log.debug("Successfully retrieved watchlists")
        except Exception as err:
            self.log.error(err)
            return None

        for watchlist in watchlists:
            if watchlist.name == self.config.WATCHLIST_NAME:
                self.log.info("Connector watchlist has already been created.")
                return watchlist

        self.log.info("Connector watchlist has not been created.")
        return None

    def create_watchlist(self):
        """
        Create watchlist for connector if not already created
        :return: watchlist object for connector
        """
        try:
            builder = Watchlist.create(self.api, self.config.WATCHLIST_NAME)
            builder.set_description(self.config.WATCHLIST_DESCRIPTION)
            watchlist = builder.build()
            watchlist.save()
            self.log.info("Connector watchlist %s created successfully" % self.config.WATCHLIST_NAME)
            return watchlist
        except Exception as err:
            self.log.error(err)
            return None

    def create_report(self, watchlist, iocv2_objects, sample_data, sample_vtis):
        """
        Create VMRAY IOC Report for sample with IOC's and VTI's
        :param watchlist: watchlist object for connector
        :param iocv2_objects: list of IOCV2 objects for sample
        :param sample_data: dict object which contains summary data about sample
        :param sample_vtis: list of dict objects which contains summary data about VTI's
        :return: void
        """
        title = "[%s] VMRAY Report for %s" % (sample_data["sample_verdict"].upper(), sample_data["sample_sha256hash"])
        description = sample_data["sample_webif_url"]

        severity = 0
        if sample_data["sample_vti_score"].isnumeric():
            severity = math.floor(int(sample_data["sample_vti_score"]) / 10)
        elif sample_data["sample_vti_score"] == VERDICT.SUSPICIOUS:
            severity = 5
        elif sample_data["sample_vti_score"] == VERDICT.MALICIOUS:
            severity = 10

        tags = []
        tags.extend(sample_data["sample_classifications"])
        tags.extend(sample_data["sample_threat_names"])
        tags.extend(list(set([vti["operation"] for vti in sample_vtis])))

        try:
            builder = Report.create(self.api, title=title, description=description, severity=severity, tags=tags)
            report = builder.build()
            report.append_iocs(iocv2_objects)
            report.save_watchlist()
            watchlist.add_reports([report])
            self.log.info("Report for sample %s created successfully" % sample_data["sample_sha256hash"])
        except Exception as err:
            self.log.error(err)

    def create_iocv2_objects(self, ioc_data, sample_data, old_iocs):
        """
        Create IOC objects with VMRAY IOC values to import CarbonBlack
        :param ioc_data: list of IOC dicts which extracted from VMRAY
        :param sample_data: dict object which contains summary data about sample
        :param old_iocs: list of IOC values which extracted from CarbonBlack for checking duplicate IOC values
        :return ioc_objects: list of IOCV2 objects
        """
        ioc_objects = []
        for key in ioc_data:
            if key in IOC_FIELD_MAPPINGS.keys():
                for ioc_field in IOC_FIELD_MAPPINGS[key]:

                    ioc_value = ioc_data[key]

                    if type(ioc_value) == set and len(ioc_value) > 0:

                        duplicate_iocs = list(ioc_value & set(old_iocs))
                        for duplicate_ioc in duplicate_iocs:
                            ioc_value.remove(duplicate_ioc)

                        for ioc in ioc_value:
                            ioc_v2 = IOC_V2.create_equality(self.api, None, ioc_field, clean_string(ioc))
                            ioc_v2.link = sample_data["sample_webif_url"]
                            ioc_objects.append(ioc_v2)

                    elif type(ioc_value) != set and ioc_value is not None:
                        if ioc_value not in old_iocs:
                            ioc_v2 = IOC_V2.create_equality(self.api, None, ioc_field, clean_string(ioc_value))
                            ioc_v2.link = sample_data["sample_webif_url"]
                            ioc_objects.append(ioc_v2)

        return ioc_objects

    def auto_ban_sample(self, sha256):
        """
        Ban malicious or suspicious processes in CarbonBlack based on SHA256 hash value
        :param sha256: Hash value of sample
        :return: void
        """
        reputation_override_object = {
            "description": self.config.AUTO_BAN_DESCRIPTION,
            "override_list": "BLACK_LIST",
            "override_type": "SHA256",
            "sha256_hash": sha256,
        }
        try:
            ReputationOverride.create(self.api, reputation_override_object)
            self.log.info("Sample %s added into BLACK_LIST" % sha256)
        except Exception as err:
            self.log.error(err)
