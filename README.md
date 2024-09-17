# maltiverse-suricata-rule-converter
Script that converts a Maltiverse Threat Intelligence Feed to Suricata rules

```
usage: suricata-rule-converter.py [-h] --maltiverse_api_key MALTIVERSE_API_KEY --feed_id FEED_ID [--sid_start SID_START] [--output_file OUTPUT_FILE]

options:
  -h, --help            show this help message and exit
  --maltiverse_api_key MALTIVERSE_API_KEY
                        Specifies Maltiverse API KEY. Required
  --feed_id FEED_ID     Specifies Maltiverse Feed ID to upload to CrowdStrike Falcon cloud.
  --sid_start SID_START
                        Specifies Suricata SID start. The generated rules will have an incremental SID starting from the specified
  --output_file OUTPUT_FILE
                        Specify output file to save the rules

```
