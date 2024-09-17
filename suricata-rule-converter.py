#!/usr/bin/python3

# -----------------------------------------------------------
# Python client that retrieves a feed from Maltiverse.com
# And converts it to Suricata Rules
#
# (C) 2024 Maltiverse
# Released under Creative Commons Universal
# -----------------------------------------------------------

import argparse
import requests
import json
import time
from datetime import datetime, timedelta, timezone


IOC_EXPIRATION_DAYS = 1


class MaltiverseSuricataConverterHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.maltiverse.com"
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    def get_feed_metadata_from_maltiverse(self, feed_id):
        """
        Gets a feed metadata from Maltiverse given its Id.
        """
        url = f"{self.base_url}/feed/{feed_id}"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def download_feed_from_maltiverse(self, feed_id):
        """
        Downloads a feed from Maltiverse given its Id.
        """
        url = f"{self.base_url}/feed/{feed_id}/download"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def convert_maltiverse_feed_to_suricata(self, feed_id, sid_start=1000001):
        """
        Converts a maltiverse feed in its original format to a Suricata format
        """
        rules = []

        rule_template_ip = 'alert ip any any -> {} any (msg:"{} - {}"; sid:{}; rev:1;)'
        rule_template_hostname = 'alert dns any any -> any any (msg:"{} - {}"; content:"{}"; fast_pattern; sid:{}; rev:1;)'

        raw_maltiverse_feed = self.download_feed_from_maltiverse(feed_id)

        for idx, element in enumerate(raw_maltiverse_feed):

            sid = sid_start + idx
            if element["type"] == "ip":
                msg = "Contact with Malicious IP "
                for bl in element["blacklist"]:
                    msg = msg + bl["description"] + "(" + bl["source"] + ") "
                rule = rule_template_ip.format(
                    element["ip_addr"], element["ip_addr"], msg, sid
                )
                rules.append(rule)
            if element["type"] == "hostname":
                msg = "Contact with Malicious Domain "
                for bl in element["blacklist"]:
                    msg = msg + bl["description"] + "(" + bl["source"] + ") "
                rule = rule_template_hostname.format(
                    element["hostname"], msg, element["hostname"], sid
                )
                rules.append(rule)
        return rules


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--maltiverse_api_key",
        dest="maltiverse_api_key",
        required=True,
        help="Specifies Maltiverse API KEY. Required",
    )
    parser.add_argument(
        "--feed_id",
        dest="feed_id",
        required=True,
        help="Specifies Maltiverse Feed ID to upload to CrowdStrike Falcon cloud.",
    )
    parser.add_argument(
        "--sid_start",
        dest="sid_start",
        default=1000001,
        help="Specifies Suricata SID start. The generated rules will have an incremental SID starting from the specified",
    )

    parser.add_argument(
        "--output_file",
        type=str,
        default=None,
        help="Specify output file to save the rules",
    )

    arguments = parser.parse_args()

    handler = MaltiverseSuricataConverterHandler(
        arguments.maltiverse_api_key,
    )
    rules = handler.convert_maltiverse_feed_to_suricata(
        arguments.feed_id,
        sid_start=int(arguments.sid_start),
    )

    # Output the rules to the console or file
    if arguments.output_file:
        with open(arguments.output_file, "w") as f:
            for rule in rules:
                f.write(rule + "\n")
    else:
        for rule in rules:
            print(rule)
