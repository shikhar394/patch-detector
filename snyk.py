import argparse
import json
import os
import re

import git

import rabbitMQ_handler
from VersionComparisonClass import CheckVersion

# Static variable to keep vulnerabilities map in memory
SNYK_VULNERABILITIES_MAP = None #Stores CVE:{Package#:XXX, Version:XXX}


def get_oracle_data(vulnerabilities_id, version_to_check):
    """
    Caches the Vulnerability.json in VULNERABILITIES_MAP
    Access the package name, range from the map.
    Uses the CheckVersion class from VersionComaprisonClass.py to compare the
    version to the range.
    Returns bool.
    """
    global SNYK_VULNERABILITIES_MAP
    if SNYK_VULNERABILITIES_MAP is None:
        with open("VulnerabilityMap.json") as f:
            SNYK_VULNERABILITIES_MAP = json.load(f)
    vulnerability_details = SNYK_VULNERABILITIES_MAP[vulnerabilities_id]
    VersionRange = vulnerability_details['Versions']
    version_comparison_obj = CheckVersion(VersionRange, version_to_check)
    return version_comparison_obj.CheckVersionInRange()


def build_vulnerability_map(snyk_data):
    vulnerability_details = {}  # SNYK_ID:{package_name:XXX, version:XXX}
    for package in snyk_data:
        for vulnerability in snyk_data[package]:
            snyk_ID = vulnerability['id']
            vulnerability_details[snyk_ID] = {}
            vulnerability_details[snyk_ID]['PackageName'] = package
            vulnerability_details[snyk_ID]['Version'] = [vulnerability_range for
                                                         vulnerability_range in
                                                         vulnerability['semver']['vulnerable']]
    return vulnerability_details


def parse_snyk(snyk_data):

    parsed_messages = []

    for item in snyk_data:
        for vulnerability in snyk_data[item]:

            snyk_id = vulnerability["id"]

            # Some vulnerabilities don't have a CVE
            cve_id = vulnerability["identifiers"]["CVE"][0] if len(vulnerability["identifiers"]["CVE"]) > 0 else ""

            repo_address = ""
            commit_hashes = []

            for ref in vulnerability["references"]:
                if "commit" in ref["url"]:

                    # Get git repo url and commit hash separately.
                    # Pull requests with multiple commits have "commits" on the address
                    url_parts = ref["url"].split("/commits/");
                    if len(url_parts) < 2:
                        url_parts = ref["url"].split("/commit/");

                    # Remove pull request suffix, if there
                    repo_address = url_parts[0].split("/pull/")[0]
                    commit_hashes.append(url_parts[1])

            # Send message to processing queue
            if repo_address != "" and len(commit_hashes) > 0:
                message = {'repo_address': repo_address + ".git", 'commits': commit_hashes,
                           'vulnerability_id': snyk_id, 'versions': [], "cve_id": cve_id}
                parsed_messages.append(message)

    return parsed_messages


def enqueue_messages(snyk_data):
    messages = parse_snyk(snyk_data)
    for message in messages:
        # Send message to processing queue
        rabbitMQ_handler.send_message(host, username, password, queue, message)
        print("Sent {};{};{};{}".format(message["vulnerability_id"],
                                        message["cve_id"],
                                        message["repo_address"],
                                        message["commits"]))


def clone_repos(snyk_data):
    messages = parse_snyk(snyk_data)

    for message in messages:
        repo_address = message["repo_address"]

        # Get a normalized folder name for the repo address
        folder_name = re.sub("\.|/", "_", re.sub("http(s)*://", "", repo_address))

        if not os.path.isdir(folder_name):
            git.Repo.clone_from(repo_address, folder_name)
            print("Cloned {}".format(repo_address))


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Handle SNYK data
        '''
    )

    parser.add_argument(
        '--config',
        default='config.json',
        type=argparse.FileType('r'),
        metavar='path',
        help='JSON config file'
    )

    parser.add_argument(
        '--vulnerability-map',
        action='store_true',
        help='Dumps vulnerability map from SNYK data to a JSON file'
    )

    parser.add_argument(
        '--clone-repos',
        action='store_true',
        help='Clones all repos locally.'
    )

    parser.add_argument(
        '--file',
        type=argparse.FileType('r', encoding='utf-8'),
        required=True,
        metavar='path',
        help='JSON SNYK data file'
    )

    return parser.parse_args()


if __name__ == '__main__':

    args = process_arguments()

    config = json.load(args.config)
    data = json.load(args.file)

    host = config["rabbitmq_host"]
    username = config["rabbitmq_username"]
    password = config["rabbitmq_password"]
    queue = config["rabbitmq_queue"]

    if args.vulnerability_map:
        with open("VulnerabilityMap.json", 'w') as f:
            json.dump(build_vulnerability_map(data), f, indent=4)
    elif args.clone_repos:
        clone_repos(data)
    else:
        enqueue_messages(data)
