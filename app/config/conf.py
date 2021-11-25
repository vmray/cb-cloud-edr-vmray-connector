import pathlib
import logging as log


# Carbon Black Cloud Reputations
class REPUTATION:
    ADAPTIVE_WHITE_LIST = "ADAPTIVE_WHITE_LIST"
    ADWARE = "ADWARE"
    COMMON_WHITE_LIST = "COMMON_WHITE_LIST"
    COMPANY_BLACK_LIST = "COMPANY_BLACK_LIST"
    COMPANY_WHITE_LIST = "COMPANY_WHITE_LIST"
    HEURISTIC = "HEURISTIC"
    IGNORE = "IGNORE"
    KNOWN_MALWARE = "KNOWN_MALWARE"
    LOCAL_WHITE = "LOCAL_WHITE"
    NOT_LISTED = "NOT_LISTED"
    PUP = "PUP"
    RESOLVING = "RESOLVING"
    SUSPECT_MALWARE = "SUSPECT_MALWARE"
    TRUSTED_WHITE_LIST = "TRUSTED_WHITE_LIST"


# VMRay product types enum
class VMRayProductType:
    ANALYZER = 0
    DETECTOR = 1


# VMRay verdicts enum
class VERDICT:
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# VMRay analyzer modes
class ANALYZER_MODE:
    REPUTATION = "reputation"
    REPUTATION_STATIC = "reputation_static"
    REPUTATION_STATIC_DYNAMIC = "reputation_static_dynamic"
    STATIC_DYNAMIC = "static_dynamic"
    STATIC = "static"


# VMRay job status
class JOB_STATUS:
    QUEUED = "queued"
    INWORK = "inwork"


# Runtime mode of connector
class RUNTIME_MODE:
    DOCKER = "DOCKER"
    CLI = "CLI"


# Build raw exlusion filters based on selected reputation filters
def build_exclusion_query(reputation_filters):
    if len(reputation_filters) > 0:
        filters = ["!process_effective_reputation:%s" % reputation for reputation in reputation_filters]
        return " AND ".join(filters)
    else:
        return None


# VMRay Configuration
class VMRayConfig:
    # VMRay Produty type setting
    PRODUCT_TYPE = VMRayProductType.ANALYZER

    # VMRay Product Analyzer or Detector API KEY
    API_KEY = "<API_KEY>"

    # VMRay REST API URL
    URL = "https://eu.cloud.vmray.com"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = "Sample from VMRay CarbonBlack Connector"

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["CarbonBlackCloud"]

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # VMRay analysis job timeout for wait_submissions
    ANALYSIS_JOB_TIMEOUT = 300

    # Analyzer mode for truncated samples
    # Carbon Black truncates files bigger than 25MB
    # If you want to run dinamic analysis for these samples change value accordingly
    TRUNCATED_FILE_ANALYZER_MODE = ANALYZER_MODE.REPUTATION_STATIC


# CarbonBlack Configuration
class CarbonBlackConfig:
    # CarbonBlack API configuration profile
    PROFILE = "default"

    # Configuration directory
    CONFIG_DIR = pathlib.Path("config")

    # Configuration file path
    CONFIG_FILE_PATH = CONFIG_DIR / pathlib.Path("cbc-config.cbc")

    # Alert/Event polling time span as seconds
    TIME_SPAN = 36000

    # Reputation filters to exclude alerts and events
    REPUTATION_FILTERS = [REPUTATION.TRUSTED_WHITE_LIST,
                          REPUTATION.LOCAL_WHITE,
                          REPUTATION.COMPANY_WHITE_LIST,
                          REPUTATION.COMMON_WHITE_LIST,
                          REPUTATION.ADAPTIVE_WHITE_LIST]

    # Carbon Black Cloud exclusion query based on reputation filters above
    EXCLUSION_QUERY = build_exclusion_query(REPUTATION_FILTERS)

    # Download directory name
    DOWNLOAD_DIR = pathlib.Path("downloads")

    # Download directory path
    DOWNLOAD_DIR_PATH = pathlib.Path(__file__).parent.parent.resolve() / DOWNLOAD_DIR

    # Max enriched event count per request
    MAX_ENRICHED_EVENT_COUNT = 10000

    # CarbonBlack Watchlist name
    WATCHLIST_NAME = "VMRay Connector"

    # CarbonBlack Watchlist description
    WATCHLIST_DESCRIPTION = "VMRay Connector Watchlist"

    # Ban process with SHA256 hash values in Carbon Black
    AUTO_BAN = False

    # Selected verdicts to ban processes automatically
    AUTO_BAN_VERDICTS = [VERDICT.MALICIOUS]

    # Description for banned processes
    AUTO_BAN_DESCRIPTION = "Detected as malicious by VMRay"


# General Configuration
class GeneralConfig:
    # Log directory
    LOG_DIR = pathlib.Path("log")

    # Log file path
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("cbc-connector.log")

    # Log verbosity level
    LOG_LEVEL = log.INFO

    # Selected verdicts for processing
    SELECTED_VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]

    # Time span between script iterations
    TIME_SPAN = 300

    # Runtime mode for script
    # If selected as CLI, script works only once, you need to create cron job for continuos processing
    # If selected as DOCKER, scripts works continuously with TIME_SPAN above
    RUNTIME_MODE = RUNTIME_MODE.DOCKER


# VMRay IOC and CarbonBlack search field mappings
# You can enable or disable IOC values with comments
# https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/platform-search-fields/
IOC_FIELD_MAPPINGS = {
    "ipv4": ["netconn_ipv4"],

    "sha256": ["process_sha256", "childproc_sha256", "fileless_scriptload_sha256", "scriptload_sha256",
               "filemod_sha256", "modload_sha256"],

    "domain": ["netconn_domain"],

    "reg_key": ["regmod_name"],

    "cmdline": ["process_cmdline"],

    "image_name": ["process_name"],

    "file_name": ["filemod_name"]
}
