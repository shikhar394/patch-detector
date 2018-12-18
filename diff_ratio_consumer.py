#!/patch-detector/venv/bin python

import argparse
import json
import os
import random
import re
import sys

import git

import detector
import mongo_handler
import rabbitMQ_handler
import runner


def consume(github_address, vulnerability_id, cve_id, commit_hashes, persister, versions=None):
    """
        Consume information from a patch_detection task (message from RabbitMQ queue) to run patch_detector and
        save results with persister.
    :param github_address: github repository address
    :param vulnerability_id: the ID of the vulnerability
    :param commit_hashes: list of commit hashes from github to extract patches for evaluation
    :param persister: function to save results with signature handle(str: commit_hash, dict: patch_detector_results)
    :param versions: selected tags on github to be evaluated. If None provided, all tags are evaluated.
    """
    # 1. Get git repo
    repo = clone_or_open_repo(github_address)

    # 2. Process all given commit hashes into a single patch
    patch = ""
    for commit_hash in commit_hashes:

        try:
            # 3. Get patch from hash
            patch += repo.git.show(commit_hash) + "\n\n"

        except git.GitCommandError:
            # Maybe repo is being cloned by another thread.
            # Return False to put it back on the queue
            return False

    # 4. Save patch to file
    temp_patch_filename = "temp_file_" + str(random.randint(0, sys.maxsize)) + ".patch"
    with open(temp_patch_filename, "w") as patch_file:
        patch_file.write(patch)

    # 5. Create config object
    args = [temp_patch_filename, repo.working_dir]
    config = runner.process_arguments(args)
    config.versions = versions

    # 6. Run evaluation
    success = False
    version_results = runner.run_git(config, detector.run)

    if version_results is not None:
        runner.determine_vulnerability_status(config, version_results)
        success = True

    # 7. Save to database
    if success:
        success = persister(github_address, vulnerability_id, cve_id, ",".join(commit_hashes), version_results)

    # 8. Delete temp resources
    os.remove(temp_patch_filename)
    
    return success


def unpack_message(message):
    # Example of message
    # message = {"repo_address": "http://github.com",
    #            "commits": ["asdfsdg", "afdgsfgrgdfs", "ghhgfdasdgfh"],
    #            "vulnerability_id": "CVE-001",
    #            "versions": ["1.0.0", "2.0.0"]}

    github_address = message["repo_address"]
    commit_hashes = message["commits"]
    vulnerability_id = message["vulnerability_id"]
    cve_id = message.get("cve_id","")
    versions = ",".join(message["versions"]) if ("versions" in message and len(message["versions"]) > 0) else None

    return github_address, commit_hashes, vulnerability_id, cve_id, versions


def clone_or_open_repo(repo_address):

    # Get a normalized folder name for the repo address
    folder_name = re.sub("\.|/", "_", re.sub("http(s)*://", "", repo_address))

    if os.path.isdir(folder_name):
        return git.Repo(path=folder_name)
    else:
        return git.Repo.clone_from(repo_address, folder_name)


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Run patch_detector listening to messages from RabbitMQ and storing to MongoDB
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
        '--single-run',
        nargs='*',
        metavar='parameter',
        help='Perform a single run locally with given parameters vulnerability_id repo_address commit VERSION_1 ... VERSION_N'
    )

    return parser.parse_args()


def listen_messages(config):

    rabbitmq_host = config["rabbitmq_host"]
    rabbitmq_username = config["rabbitmq_username"]
    rabbitmq_password = config["rabbitmq_password"]
    rabbitmq_queue = config["rabbitmq_queue"]

    mongodb_host = config["mongodb_host"]
    mongodb_username = config["mongodb_username"]
    mongodb_password = config["mongodb_password"]
    mongodb_database = config["mongodb_database"]

    # Persister call
    def persist_to_mongo(github_address, vulnerability_id, cve_id, commit_hash, results):
        return mongo_handler.save_vulnerability_results(mongodb_host, mongodb_username, mongodb_password,
                                                        mongodb_database, github_address, vulnerability_id, cve_id,
                                                        commit_hash, results)

    # Consumer call
    def handle_message_body(body):
        received_msg = json.loads(body)
        print("Dequeued message {}".format(received_msg))

        github_address, commit_hashes, vulnerability_id, cve_id, versions = unpack_message(received_msg)
        success = consume(github_address, vulnerability_id, cve_id, commit_hashes, persist_to_mongo, versions)

        # Keep failed messages into an error queue
        if not success:
            rabbitMQ_handler.send_message(rabbitmq_host, rabbitmq_username, rabbitmq_password,
                                          rabbitmq_queue + "_error", received_msg)
        return True

    rabbitMQ_handler.listen_messages(rabbitmq_host, rabbitmq_username, rabbitmq_password, rabbitmq_queue,
                                     handle_message_body)


def single_run(args):

    def persister(github_address, vulnerability_id, cve_id, commit_hash, results):
        print(results)

    vulnerability_id = args.single_run[0]
    repo_address = args.single_run[1]
    commit_hashes = [args.single_run[2]]
    versions = args.single_run[3:]
    versions = ",".join(versions) if (versions is not None and len(versions) > 0) else None

    consume(repo_address, vulnerability_id, commit_hashes, persister, versions)


if __name__ == '__main__':

    args = process_arguments()
    config = json.load(args.config)

    if args.single_run:
        single_run(args)
    else:
        listen_messages(config)
