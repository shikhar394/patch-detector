import argparse
import json
import re

import snyk

from pymongo import MongoClient, UpdateOne
from pymongo.errors import ConnectionFailure


def wrap_mongo_objects(repo_address, vulnerability_id, cve_id, patch_commit_hash, patch_evaluation_results):
    """
        Converts patch detector results into objects insertable into a MongoDB. Objects can be identified by
        (repo_address, vulnerability_id, patch_commit_hash).
    :param repo_address: github repository address
    :param vulnerability_id: an ID such as CVE-0001
    :param patch_commit_hash: the commit hash from github
    :param patch_evaluation_results: the results dict object from patch_detector
    :return: MongoDB objects
    :rtype: list of dict
    """
    objs = []

    for version, results in patch_evaluation_results.items():

        breakdown = results["breakdown"]
        new_breakdown = []
        for file, stats in breakdown.items():
            file_stats = stats
            file_stats["file"] = file
            new_breakdown.append(file_stats)
        results["breakdown"] = new_breakdown

        obj = {"repository": repo_address, "version": version, "vulnerability_id": vulnerability_id, "cve_id": cve_id,
               "commit": patch_commit_hash,
               "results": results}
        objs.append(obj)

    return objs


def save_vulnerability_results(host, username, password, database, repo_address, vulnerability_id, cve_id,
                               patch_commit_hash, patch_evaluation_results):
    client = MongoClient("mongodb://{}:{}@{}:27017".format(username, password, host))
    db = client[database]

    try:
        # The ismaster command is cheap.
        client.admin.command('ismaster')
    except ConnectionFailure:
        print("Mongo server not available")
        return False

    collection = db.vulnerabilities

    mongo_objects = wrap_mongo_objects(repo_address, vulnerability_id, cve_id, patch_commit_hash, patch_evaluation_results)

    if mongo_objects and len(mongo_objects) > 0:

        bulk_requests = [UpdateOne({"repository": mongo_obj["repository"],
                                    "vulnerability_id": mongo_obj["vulnerability_id"],
                                    "version": mongo_obj["version"]}, {"$set": mongo_obj}, upsert=True)
                         for mongo_obj in mongo_objects]

        bulk_result = collection.bulk_write(bulk_requests)
        success = (bulk_result.inserted_count + bulk_result.upserted_count) > 0

        if success:
            print("Persisted vulnerability {} with hash {}".format(vulnerability_id, patch_commit_hash))
        else:
            print("Vulnerability {} not persisted".format(vulnerability_id))
    else:
        print("Nothing persisted from vulnerability {} with hash {}".format(vulnerability_id, patch_commit_hash))
        success = True

    return success


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            MongoDB persister. Default main run dumps data from MongoDB into CSV.
        '''
    )

    parser.add_argument(
        '--config',
        default='config.json',
        type=argparse.FileType('r'),
        metavar='path',
        help='JSON config file'
    )

    return parser.parse_args()


def main():
    args = process_arguments()
    config = json.load(args.config)

    host = config["mongodb_host"]
    username = config["mongodb_username"]
    password = config["mongodb_password"]
    database = config["mongodb_database"]

    # # Usage example of saving to MongoDB
    # vulnerability_results = {
    #     '1.0.0': {'overall': {'additions': 0.0, 'deletions': 0.3333333333333333, 'confident': True}, 'breakdown': {
    #         'runner.py': {'additions': 0.0, 'deletions': 0.3333333333333333, 'status': 'unchanged'}},
    #               'vulnerable': True},
    #     '2.0.0': {'overall': {'additions': 0.0, 'deletions': 0.0, 'confident': True},
    #               'breakdown': {'runner.py': {'additions': 0.0, 'deletions': 0.0, 'status': 'unchanged'}},
    #               'vulnerable': True}}
    #
    # save_vulnerability_results(host, username, password, database,
    #                            "repo_git", "NVD-001", "hash1", vulnerability_results)

    # Checking saved results
    client = MongoClient("mongodb://{}:{}@{}:27017".format(username, password, host))
    db = client[database]

    try:
        # The ismaster command is cheap.
        client.admin.command('ismaster')
    except ConnectionFailure:
        print("Server not available")

    collection = db.vulnerabilities
    dump_vulnerabilities(collection)


def dump_vulnerabilities(collection):

    # Regex to strip versions in format x.x.x...
    version_regex = re.compile('\d+(\.\d+)+.*')

    # CSV header
    print("CVE ID;"
          "Version;"
          "Stripped version;"
          "Additions ratio;"
          "Deletions ratio;"
          "Patch-detector vulnerable result;"
          "Oracle vulnerable result;"
          "True positive;"
          "True negative;"
          "False positive;"
          "False negative")

    for obj in collection.find():

        stripped_version = version_regex.search(obj["version"].replace("_", "."))

        # Do not print tags that don't express a clear version
        if stripped_version:

            oracle = get_oracle(obj["vulnerability_id"], obj["version"])
            true_positive = int(bool(obj["results"]["vulnerable"]) == oracle and oracle is True)
            true_negative = int(bool(obj["results"]["vulnerable"]) == oracle and oracle is False)
            false_positive = int(bool(obj["results"]["vulnerable"]) != oracle and oracle is False)
            false_negative = int(bool(obj["results"]["vulnerable"]) != oracle and oracle is True)

            print("{};{};{};{};{};{};{};{};{};{};{}".format(obj["vulnerability_id"],
                                                            obj["version"],
                                                            stripped_version.group(),
                                                            obj["results"]['overall']['additions'],
                                                            obj["results"]['overall']['deletions'],
                                                            obj["results"]["vulnerable"],
                                                            oracle,
                                                            true_positive,
                                                            true_negative,
                                                            false_positive,
                                                            false_negative))


# Static variable to keep vulnerabilities map in memory
vulnerabilities_map = {}


def get_oracle(vulnerability_id, version):
    vulnerabilities_folder = "experiments/vulnerabilities/"

    if vulnerability_id in vulnerabilities_map:
        vulnerable_versions = vulnerabilities_map[vulnerability_id]
    else:
        file = vulnerabilities_folder + vulnerability_id + "_vulnerability.txt"

        with open(file, 'r') as f:
            vulnerable_versions = [line.strip() for line in f.readlines()]

        vulnerabilities_map[vulnerability_id] = vulnerable_versions

    if version not in vulnerable_versions:
        return snyk.get_oracle_data(vulnerability_id, version)
    else:
        return True


if __name__ == '__main__':
    main()
