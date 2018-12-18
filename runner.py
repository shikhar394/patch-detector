#!/usr/bin/env python3

import argparse
import json
import os
import pkg_resources
import re
import sys
import git
import tqdm
import detector
import clone_detector
import active_learning_rounds
import resolver
import util


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def error(message, fatal=False):
    print(
        '{0}{1}ERROR:{3} {2}'.format(Color.BOLD, Color.RED, message, Color.END)
    )

    if fatal:
        sys.exit(1)


def dump_results(version_results):
    for version, results in version_results.items():
        print(
            '{0}{1}\n{2}{3}'.format(
                Color.BOLD, version, '=' * len(version), Color.END
            )
        )

        for file, ratio in results.items():
            print('{0}: {1}'.format(file, str(ratio)))


def run(config, detection_call):
    full_path = os.path.abspath(config.project)

    git_path = os.path.join(full_path, '.git')
    svn_path = os.path.join(full_path, '.svn')
    cvs_path = os.path.join(full_path, '.cvs')

    if os.path.exists(git_path):
        return run_git(config, detection_call)
    elif os.path.exists(svn_path):
        return run_svn(config)
    elif os.path.exists(cvs_path):
        return run_cvs(config)
    else:
        return run_dir(config)


def run_git(config, detection_call):
    """
        Run detection method with the provided patch for the provided repo on the provided versions (or all versions
        if none provided).
    :param config: Config object with all parameters
    :param detection_call: Visitor callback method to evaluate each version in a form detection(config, version_diff)
    :return: a results dictionary
    :rtype: dict
    """
    sha1_regex = re.compile('([a-f0-9]{40})')

    full_path = os.path.abspath(config.project)

    try:
        repo = git.Repo(full_path)
    except git.exc.InvalidGitRepositoryError:
        error('project path is not a valid git repository', True)

    try:
        active_branch = repo.active_branch
    except TypeError:
        if len(repo.branches) == 1:
            active_branch = repo.branches[0]
            repo.git.checkout(active_branch, force=True)
        else:
            error('Repository is in a detached HEAD state ' +
                  'and could not determine default branch.', True)

    if config.start_version:
        start_version = pkg_resources.parse_version(config.start_version)
    else:
        start_version = pkg_resources.SetuptoolsLegacyVersion('0.0.0')

    versions = []
    if config.versions:
        try:
            if os.path.exists(config.versions):
                with open(config.versions, 'r') as file:
                    versions = file.read().strip().split('\n')
            else:
                versions = config.versions.strip().split(',')
        except TypeError:
            versions = config.versions.strip().split(',')
    else:
        for tag in repo.tags:
            if start_version <= pkg_resources.parse_version(tag.name):
                versions.append(tag.name)

    if not config.debug:
        versions = tqdm.tqdm(versions)

    version_results = {}
    patch_text = config.patch.read()
    patch = util.load_patch(patch_text)

    match = sha1_regex.match(patch_text.split()[1])

    if match:
        sha = match.group(1)
    else:
        raise Exception('No commit hash found in patch')

    if config.debug:
        print('Starting from commit sha {}'.format(sha))

    try:
        for version in versions:

            if version not in repo.tags:
                raise ValueError('No such version "{}"'.format(version))

            # Get the version commit and diff it with the fixed version (the patch hash)
            # The "a" side is the evaluated version, the "b" side is the patch
            # The diff shows what "a" needs to become "b"
            # The diff is a instance of 'git.diff.DiffIndex'
            # The object 'git.diff.DiffIndex' is an array of objects 'git.diff.Diff'
            # The object 'git.diff.Diff' prints the diff, so I can parse it as a patch
            commit = repo.commit(version)
            version_diff = commit.diff(sha, create_patch=True)

            diffs = []
            for diff in patch:
                result = resolver.resolve_path(
                    repo, sha, version, diff.header.new_path, config.debug
                )

                if config.debug:
                    print(result)

                header = diff.header._replace(path=result[0], status=result[1])

                adjusted_diff = diff._replace(header=header)
                diffs.append(adjusted_diff)

            config.patch = diffs

            # Call visitor detection method on current version with parameters in the config dictionary
            version_results[version] = detection_call(config, version_diff)

            if config.debug:
                print('Removing {0}'.format(version))
    except KeyboardInterrupt:
        pass
    except AssertionError:
        error('assertion failed!')
        version_results = None
    except Exception as e:
        error(str(e))
        version_results = None
    finally:
        print('\r', end='')

    return version_results


def run_svn(config):
    pass


def run_cvs(config):
    pass


def run_dir(config):
    runner_config = config
    for version in os.listdir(config.project):
        full_path = os.path.join(config.project, version)


def determine_vulnerability_status(config, version_results):
    for version, result in version_results.items():
        if result['overall']['confident']:
            additions = result['overall']['additions']
            deletions = result['overall']['deletions']

            result['vulnerable'] = True

            # Deletions None is the same as 1
            # Additions None is the same as 0
            if (deletions is None or (deletions is not None and deletions >= config.deletions_threshold)) and \
                    (additions is not None and additions >= config.additions_threshold):
                result['vulnerable'] = False
        else:
            result['vulnerable'] = 'indeterminate'


def process_arguments(args=None):
    parser = argparse.ArgumentParser(
        description='''
            Checkout each version of a codebase and run a patch check
            against it.
        '''
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Turn on debugging'
    )

    parser.add_argument(
        '--results',
        type=argparse.FileType('w+'),
        default=sys.stdout,
        help='Path to store the results'
    )

    parser.add_argument(
        '--features',
        type=argparse.FileType('r'),
        metavar='path',
        help='Features values to be evaluated for active learning'
    )

    parser.add_argument(
        '--additions-threshold',
        type=float,
        default=0.5,
        metavar='0.0..1.0',
        help='Threshold that must be met to satisfy the invulnerable requirement'
    )

    parser.add_argument(
        '--deletions-threshold',
        type=float,
        default=0.25,
        metavar='0.0..1.0',
        help='Threshold that must be met to satisfy the invulnerable requirement'
    )

    parser.add_argument(
        '--start-version',
        metavar='VERSION',
        help='Version at which to start; ignored if using --versions'
    )

    parser.add_argument(
        '--versions',
        help='Comma separated list of versions against which to execute'
    )

    parser.add_argument(
        '--method',
        default='diff_ratios',
        option_strings=['diff_ratios', 'active_learning'],
        metavar='line_ratios|active_learning',
        help='Which method to be applied for detecting patch deployment'
    )

    parser.add_argument(
        '--vulnerable-versions',
        type=argparse.FileType('r'),
        metavar='path',
        help='The file path with a list of vulnerable versions to be used in the active learning process'
    )

    parser.add_argument(
        '--training-versions',
        type=str,
        nargs='+',
        metavar='VERSION_1 VERSION_2 ... VERSION_N',
        help='Versions to be used as training data from the oracle'
    )

    parser.add_argument(
        'patch',
        type=argparse.FileType('r'),
        help='Path to the patch to be tested'
    )

    parser.add_argument(
        'project',
        help='Path to the root of the project repository'
    )

    return parser.parse_args(args)


def main():
    config = process_arguments()

    print('''
            {0}Project:{3} {2}
            {0}  Patch:{3} {1}
        '''.format(
        Color.BOLD,
        os.path.basename(config.patch.name),
        os.path.abspath(config.project),
        Color.END
    )
    )

    if config.method == 'diff_ratios':
        print("Running diff ratios method")
        version_results = run(config, detector.run)
        determine_vulnerability_status(config, version_results)

        if version_results:
            json.dump(version_results, config.results, sort_keys=True, indent=4)

    elif config.method == 'active_learning':
        print("Running active learning method")
        config.features = open(config.results.name, "r")
        version_results = run(config, clone_detector.evaluate_version)

        json.dump(version_results, config.results, sort_keys=True, indent=4)

        config.results = version_results

        if config.vulnerable_versions and config.training_versions:
            active_learning_rounds.run_active_learning_rounds(config)

    else:
        print("Running method not correctly defined.")


if __name__ == '__main__':
    main()
