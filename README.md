# VMWare Carbon Black Cloud Connector for VMRay Analyzer 

**Latest Version:** 1.1 - **Release Date:** 03/20/2022

## Overview

This project is an integration between VMWare Carbon Black Cloud Enterprise EDR and VMRay Analyzer. Connector will collect unique SHA256 hash values of processes and query or submit these samples into VMRay Sandbox. After the submission it retrieve IOC values from VMRay and creates Reports in VMware Carbon Black Cloud Enterprise EDR Watchlist.

## Project Structure

    app                             # Main project directory
    ├─── config                     # Configuration directory
    │   └─── __init__.py 			
    │   └─── cbc-config.cbc         # VMWare Carbon Black Cloud API configuration file
    │   └─── conf.py                # Connector configuration file
    ├─── downloads                  # Directory for extracted binaries
    │   └─── temp                   # Directory for downloaded archive files
    ├─── lib                        # Library directory
    │   └─── __init__.py 				
    │   └─── CarbonBlack.py         # VMWare Carbon Black API functions
    │   └─── VMRay.py               # VMRay API functions
    ├─── log                        # Log directory for connector
        └─── cbc-connector.log      # Log file for connector
    └─── __init__.py
    └─── connector.py               # Main connector application
    └─── requirements.txt           # Python library requirements
    └─── log                        # Log directory for Docker volume


## Requirements
- Python 3.x with required packages ([Required Packages](app/requirements.txt))
- VMware Carbon Black Cloud Enterprise EDR
- VMRay Analyzer
- Docker (optional)

## License

## Support

## Installation

Clone the repository into a local folder.

    git clone https://github.com/vmray/cb-cloud-edr-vmray-connector.git

Install the requirements.

    pip install -r requirements.txt
    
Edit the [cbc-config.cbc](app/config/cbc-config.cbc) and [conf.py](app/config/conf.py) files and update with your configurations.

## Configuration

### VMWare Carbon Black Cloud Configurations

- Activate file uploading to Universal Binary Store. (`Enforce > Policies > Upload all new binaries to CB for your later analysis and download`)

- Create Custom Access Level with the permissions below with web interface. (`Settings > API Access > Access Levels`)

|       Category       |   Permission Name   |    .Notation Name   |       Create       	 |        Read        	   |       Update       | Delete | Execute |
|:---------------------|:--------------------|:--------------------|:-----------------------:|:-----------------------:|:------------------:|:------:|:-------:|
| Alerts               | General Information | org.alerts| | :ballot_box_with_check: | | | |
| Applications    | Reputation | org.reputations |:ballot_box_with_check:| |:ballot_box_with_check:| | |
| Custom Detections    | Watchlists | org.watchlists|:ballot_box_with_check:| :ballot_box_with_check: |:ballot_box_with_check:| | |
| Custom Detections    | Feeds   | org.feeds | |:ballot_box_with_check:| | | |
| Device | Quarantine | device.quarantine | | | | | :ballot_box_with_check: |
| Device | General information | device | | :ballot_box_with_check:  | | | |
| Search               | Events | org.search.events | :ballot_box_with_check: | :ballot_box_with_check: | | | |
| Unified Binary Store | SHA-256 | ubs.org.sha256 | | :ballot_box_with_check: | | | |
| Unified Binary Store | File | ubs.org.file | |:ballot_box_with_check:| | | |

- Create API Key based on Custom Acccess Level with web interface. (`Settings > API Access > API Keys`)

- Edit the [cbc-config.cbc](app/config/cbc-config.cbc) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `url`               | URL of Carbon Black Cloud instance | `https://defense.conferdeploy.net` |
| `token`             | API Secret Key / API ID            | | 
| `org_key`           | Organizaton Key (`Settings > API Access > API Keys`) | |
| `ssl_verify`        | Enable or disable certificate verification [`true`/`false`] | `disabled` |
| `proxy`               | Proxy FQDN or IP address for API requests | `disabled` |
| `ignore_system_proxy` | Ignore or use system wide proxy [`true`/`false`] | `disabled` |
| `integration_name` | Custom user agent for API requests  | `VMRayCarbonBlackConnector/1.0.0` |

- Edit the `CarbonBlackConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `PROFILE`          | Configuration profile name | `default` |
| `PATH`             | Configuration file path    | `./config/cbc-config.cbc` |
| `TIME_SPAN`        | Polling time span for alerts/events as seconds  | `18000` |
| `REPUTATION_FILTERS` | Reputation filters to exclude alerts and events based on whitelists  | `TRUSTED_WHITE_LIST, LOCAL_WHITE, COMPANY_WHITE_LIST, COMMON_WHITE_LIST, ADAPTIVE_WHITE_LIST` |
| `DEVICE_OS_FILTERS` | Device operating system filter to include selected operating systems | `WINDOWS`|
| `DOWNLOAD_DIR_NAME`      | Directory for downloaded archives | `temp` |
| `EXTRACT_DIR_NAME`     | Directory for extracted binaries  | `downloads` |
| `MAX_ENRICHED_EVENT_COUNT` | Max retrieved enriched event count per request | `10000` |
| `WATCHLIST_NAME` | Watchlist name for connector  | `VMRay Connector` |
| `WATCHLIST_DESCRIPTION` | Watchlist description for connector  | `VMRay Connector Watchlist` |
| `AUTO_BAN` | Ban process with SHA256 hash values [`True`/`False`] | `False` |
| `AUTO_BAN_VERDICTS` | Selected verdicts to ban processes automatically | `[malicious]` |
| `AUTO_BAN_DESCRIPTION` | Description for banned processes | `Detected as malicious by VMRay` |
| `QUARANTINE` | Quarantine devices which contains malicious process | `False` |
| `QUARANTINE_VERDICTS` | Selected verdicts to quarantine devices automatically | `[malicious]` |

## VMRay Configurations

- Create API Key with web interface. (`Analysis Settings > API Keys`)

- Edit the `VMRayConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `PRODUCT_TYPE`| Enum for VMRay API Key Type [`REPORT`/`VERDICT`] | `REPORT` |
| `API_KEY`| API Key |  |
| `URL`| URL of VMRay instance | `https://eu.cloud.vmray.com` |
| `SSL_VERIFY`| Enable or disable certificate verification [`True`/`False`] | `True` |
| `SUBMISSION_COMMENT`| Comment for submitted samples | `Sample from VMRay CarbonBlack Connector` |
| `SUBMISSION_TAGS`| Tags for submitted samples | `CarbonBlackCloud` |
| `ANALYSIS_TIMEOUT`| Timeout for submission analyses as seconds | `120` |
| `MAX_JOBS`| Max job count for submissions | `3` |
| `MAX_RECURSIVE_SAMPLES`| Max count of recursive samples to analyze | `5` |
| `NORMAL_ANALYZER_MODE`| Analyzer mode for normal samples | `reputation_static_dynamic` |
| `TRUNCATED_FILE_ANALYZER_MODE`| Analyzer mode for truncated samples | `reputation_static` |

## General Connector Configurations

- Edit the `GeneralConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item  | Description       | Default |
|:--------------------|:-----------------------------------|:-------------|
| `LOG_FILE_PATH`| Connector log file path | `cbc-connector.log` |
| `LOG LEVEL`| Logging verbosity level | `INFO` |
| `SELECTED_VERDICTS`| Selected verdicts to process and report back to VMWare Carbon Black Cloud | `malicious` |
| `TIME_SPAN`| Time span between script iterations as seconds | `300` |
| `RUNTIME_MODE`| Runtime mode for script | `DOCKER` |

## IOC Configurations

- Edit the `IOC_FIELD_MAPPINGS` in [conf.py](app/config/conf.py) file. You can enable or disable IOC types with comments. Also you can add Carbon Black fields into IOC type lists for populating IOCS.

| IOC Type | Description | Carbon Black Field Names |
|:--------------------|:-----------------------------------|:-------------|
| `ipv4`| Connected IP V4 address | `netconn_ipv4` |
| `sha256`| SHA256 Hash value of process, child process, loaded script, modified file | `process_sha256, childproc_sha256, fileless_scriptload_sha256, scriptload_sha256, filemod_sha256, modload_sha256` |
| `domain`| Connected domain | `netconn_domain` |
| `reg_key`| Modified registry keys | `regmod_name` |
| `cmdline`| Sample process command line with arguments | `process_cmdline` |
| `image_name`| Sample process name | `process_name` |
| `file_name`| Sample or dropped file name | `filemod_name` |

# Running the Connector

## Running with CLI

You can start connector with command line after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.CLI` in the `GeneralConfig`. Also you can create cron job for continuous processing.
    
    python connector.py

## Running with Docker

You can create and start Docker image with Dockerfile after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.DOCKER` in the `GeneralConfig`.

    docker build -t cb_connector .
    docker run -d -v $(pwd)/log:/app/log -t cb_connector

After running the Docker container you can see connector logs in the log directory on your host machine.