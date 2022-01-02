1. Get all processes, enriched events and alerts from Carbon Black with configured timespan and exclusion filters
2. Extract unique SHA256 hashes of processes from processes, enriched events and alerts
3. Check if the hash values exist in the VMRay
    1. If yes; add sample into found_samples with sample summary
    2. If no; add sample into download_samples
4. Get all watchlists and feeds from Carbon Black
5. Extract all IOC values from watchlists and feeds to check duplicate IOC's
6. Get if the connector watchlist exists in the Carbon Black
    1. If yes; use it as watchlist object
    2. If no; create new watchlist in the Carbon Black
7. Get download urls for samples in the download_samples
8. Download and extract samples from Unified Binary Store
    1. Check if the file was truncated
        1. If yes; save truncated binary hash value
9. Check if the truncated files hashes exists in the VMRay
    1. If yes; add truncated sample into found_samples with sample summary
10. Get sample information for found_samples from VMray and check verdict
    1. If verdict in selected verdicts;
        1. Get IOC values from VMRay and parse IOC's
        2. Add sample hash value into IOC's for VMRay Detector
        3. If file was truncated, add real sample hash into IOC values
        4. Check IOC values if exists in the Carbon Black reports
            1. If not exists
                1. Create IOCV2 objects
                2. Get sample VTI's from VMRay
                3. Create report with IOC's and VTI's
                4. If auto_ban is configured, check sample verdict
                    1. If sample verdict in the auto_ban_verdicts
                        1. Ban SHA256 hash value in Carbon Black with reputation override
11. Submit downloaded samples into VMRay
12. Wait to finish analyses
    1. Get sample information for finished analyses from VMray 
    2. Check and log analysis errors
    3. Check submission verdict
    3. If verdict in selected verdicts;
        1. Get IOC values from VMRay and parse IOC's
        2. Add sample hash value into IOC's for VMRay Detector
        3. If file was truncated, add real sample hash into IOC values
        4. Check IOC values if exists in the Carbon Black reports
            1. If not exists
                1. Create IOCV2 objects
                2. Get sample VTI's from VMRay
                3. Create report with IOC's and VTI's
                4. If auto_ban is configured, check sample verdict
                    1. If sample verdict in the auto_ban_verdicts
                        1. Ban SHA256 hash value in Carbon Black with reputation override
                5. If quarantine is configured, check sample verdict
                    1. If sample verdict in the quarantine_verdicts
                        1. Get device ids with sample sha256 hash value
                        2. Quarantine devices with device_ids
15. Delete downloaded files