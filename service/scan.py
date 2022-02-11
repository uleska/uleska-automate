import json
import sys
import time

import requests

from api.scan_api import get_scans


def wait_for_scan_to_finish(host: str, token: str, print_json: bool, version: str) -> None:
    scan_finished: bool = False
    while scan_finished is False:

        status_response: requests.Response = get_scans(host, token)
        # We have a response, check to see if this scan is still running.  Note there could be multiple scans running
        try:
            running_scans_json = json.loads(status_response.text)
        except json.JSONDecodeError as jex:
            print("Invalid JSON when checking for running scans.  Exception: [" + str(jex) + "]")
            sys.exit(2)

        if len(running_scans_json) == 0:
            # If there's no scans running, then it must have finished
            if not print_json:
                print("No more scans running")
            scan_finished = True
            break

        versions_running = []

        for scan in running_scans_json:
            if 'versionId' in scan:
                versions_running.append(scan['versionId'])
            else:
                print("No versionId in the scan\n")

        if version in versions_running:
            if not print_json:
                print("Scan for version " + version + " is still running, waiting...")
            time.sleep(10)
        else:
            if not print_json:
                print("Scan for version " + version + " has completed")
            scan_finished = True
            break
