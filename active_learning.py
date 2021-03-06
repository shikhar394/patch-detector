import argparse
import json
import random
import sys

import numpy
from sklearn import preprocessing
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_recall_fscore_support
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import VotingClassifier


def active_learning_prediction(features, vulnerable_versions, training_versions, classifier="d_tree"):
    """
        Using train labels from file, predicts if versions in from result features are vulnerable using calculated features.
        Input dictionary is modified to add "vulnerable" key (bool)
    :param dict features: structured calculated features for all assessed versions
    :param list of str vulnerable_versions: the vulnerable versions oracle
    :param list of str training_versions: list of versions to be included on the training data
    :param str classifier: the classifier type to be used in the committee. Valid values: "d_tree", "nb", "svm"
    :return: current metrics and next version information
    :rtype: (list of float, list of float, str, float, str)
    """

    # Setup data for model
    features_train, labels_train, features_test, labels_test, versions_test = preprocess_features(features,
                                                                                                  vulnerable_versions,
                                                                                                  training_versions)

    committee_prediction, entropies = committee_classify(features_train, labels_train, features_test, classifier)

    not_vulnerable_metrics, vulnerable_metrics = build_evaluation(committee_prediction, entropies, features,
                                                                  versions_test, vulnerable_versions)

    # Get next training version from weighted sample
    next_version_index = get_weighed_sample(entropies)
    next_train_version = versions_test[next_version_index]
    next_train_version_entropy = entropies[next_version_index]

    # Get classification type for evaluation purposes
    if committee_prediction[next_version_index]:
        classification = "TP" if next_train_version in vulnerable_versions else "FP"
    else:
        classification = "TN" if next_train_version not in vulnerable_versions else "FN"

    # Keep training labels in results too
    for version in training_versions:
        features[version]["vulnerable"] = (version in vulnerable_versions)
        features[version]["entropy"] = 0.0

    # Return next version to be inserted into the training model
    return not_vulnerable_metrics, vulnerable_metrics, next_train_version, next_train_version_entropy, classification


def build_evaluation(committee_prediction, entropies, features, versions_test, vulnerable_versions):
    # Evaluate results
    true_vulnerability = []
    for index, version in enumerate(versions_test):
        features[version]["vulnerable"] = bool(committee_prediction[index])
        features[version]["entropy"] = entropies[index]

        # Compute correctness for versions in committee_prediction for metrics calculation
        true_vulnerability.append(version in vulnerable_versions)

    # Training versions are not considered for accuracy calculation
    not_vulnerable_metrics, vulnerable_metrics = calculate_metrics(true_vulnerability, committee_prediction)

    return not_vulnerable_metrics, vulnerable_metrics


def committee_classify(features_train, labels_train, features_test, classifier="d_tree", n_classifiers=5):
    """
        Using an ensamble committee, classifies and returns calculated entropies for given test features.
    :param numpy.array features_train: array with features to train the classifiers
    :param list of int labels_train: list of labels to train the classifiers
    :param numpy.array features_test: array with features to be classified
    :param str classifier: the classifier type to be used in the committee. Valid values: "d_tree", "nb", "svm"
    :param int n_classifiers: number of classifiers to be created in the committee
    :return: a tuple with predictions and calculated entropies
    :rtype: (list of int, numpy.array)
    """

    def d_tree(randomness):
        return DecisionTreeClassifier(criterion="entropy", splitter="random", random_state=randomness)

    def nb(randomness):
        return MultinomialNB(alpha=randomness * 0.5)

    def svm(randomness):
        kernels = [("linear", 0), ("poly", 2), ("poly", 3), ("rbf", 0), ("sigmoid", 0)]
        return SVC(kernel=kernels[randomness % len(kernels)][0], degree=kernels[randomness % len(kernels)][1])

    classifier_calls = {"d_tree": d_tree, "nb": nb, "svm": svm}

    # Necessary to scale features for svm
    if classifier == "svm":
        scaler = preprocessing.StandardScaler().fit(features_train)
        features_train = scaler.transform(features_train)
        features_test = scaler.transform(features_test)

    estimators = []
    for i in range(n_classifiers):
        # Initialize classifiers for the ensamble
        estimators.append((classifier + str(i), classifier_calls[classifier](i)))

    # Fit and predict
    eclf = VotingClassifier(estimators=estimators, voting="hard", n_jobs=-1)
    eclf.fit(features_train, labels_train)
    prediction = eclf.predict(features_test)

    # Calculate entropies. Individual votes array needs to transpose for calculating entropies with classifiers in
    # the axis 0.
    individual_votes = numpy.transpose(eclf.transform(features_test))
    entropies = calculate_entropies(individual_votes)

    return prediction, entropies


def get_versions_labels(json_file):
    """
        Reads versions labels from a json file to a dictionary.
    :param {read} json_file: the json file stream
    :return: A dictionary with versions and vulnerability state: 1 = vulnerable, 0 = not vulnerable
    :rtype: {str : int}
    """
    versions_labels = json.load(json_file)

    for version in versions_labels:
        if versions_labels[version] == "vulnerable":
            versions_labels[version] = 1
        else:
            versions_labels[version] = 0

    return versions_labels


def get_versions_from_file(versions_file):
    return versions_file.read().splitlines()


def preprocess_features(features, vulnerable_versions, training_versions):
    """
        Get results into a numpy array of versions x features
    :param {} features: dictionary structure with calculated feature values for assessed versions
    :param [str] vulnerable_versions: oracle vulnerable versions
    :param [str] training_versions: versions to collect features for the training model
    :return: a tuple with train features, train labels, test features, test labels and test versions
    :rtype: (numpy.array, list of int, numpy.array, list of int, list of str)
    """

    features_train = []
    labels_train = []
    features_test = []
    labels_test = []
    versions_test = []

    # Get all features keys to compose array of features values
    feature_keys = sorted(features[training_versions[0]]["overall"].keys())

    for version, feature_item in features.items():

        feature_values = [feature_item["overall"][key] for key in feature_keys]

        if version in training_versions:
            features_train.append(feature_values)
            labels_train.append(version in vulnerable_versions)
        else:
            features_test.append(feature_values)
            labels_test.append(version in vulnerable_versions)
            versions_test.append(version)

    return numpy.array(features_train), labels_train, numpy.array(features_test), labels_test, versions_test


def calculate_entropies(predictions):
    """
        This entropy calculates the disagreement ratio between classifiers (entropy), and classifies with the majority
        of votes from all classifiers.
    :param numpy.array predictions: the numpy array with predictions form all classifiers in the shape (n_classifiers x data points)
    :return: an array with calculated entropies
    :rtype: numpy.array
    """
    n_classifiers = predictions.shape[0]
    positive_counts = predictions.sum(axis=0)

    positive_ratio = positive_counts * numpy.full(positive_counts.shape, 1 / n_classifiers)
    negative_ratio = numpy.ones(positive_counts.shape) - positive_ratio

    # Using numpy.ma (Masked arrays) to avoid NaN with log2(0)
    # Entropy formula: H(X) = -1 * sum(P(xi)*log2(Pxi))
    # https://en.wikipedia.org/wiki/Entropy_(information_theory)
    entropies = numpy.negative(positive_ratio * numpy.ma.log2(positive_ratio).filled(0) +
                               negative_ratio * numpy.ma.log2(negative_ratio).filled(0))

    return entropies


def calculate_metrics(truth, predictions):
    """
        Calculates precision, recall, fscore, support and accuracy given two comparable lists
    :param [] truth: array with correct target values
    :param [] predictions: array with values to be avaluated
    :return: lists for vulnerable and non-vulnerable metrics with 5 float values in this order:
             [precision, recall, fscore, support, accuracy]
    :rtype: (list of float, list of float)
    """
    accuracy = accuracy_score(truth, predictions)
    metrics = numpy.array(precision_recall_fscore_support(truth, predictions))

    # Handle single dimension metrics
    if metrics.shape[1] == 1:
        not_vulnerable_metrics = metrics[:, 0].tolist() if truth == [0] else [0., 0., 0., 0.]
        vulnerable_metrics = metrics[:, 0].tolist() if truth == [1] else [0., 0., 0., 0.]
    else:
        not_vulnerable_metrics = metrics[:, 0].tolist()
        vulnerable_metrics = metrics[:, 1].tolist()

    not_vulnerable_metrics.append(accuracy)
    vulnerable_metrics.append(accuracy)

    return not_vulnerable_metrics, vulnerable_metrics


def get_weighed_sample(entropies, sampling_weight=5):
    """
        From a list of entropies, selects randomly a sample from the top sampling weight.
    :param list of float entropies: a list of entropy values
    :param int sampling_weight: the number of top samples to randomly select one
    :return: the index in the entropies list to pick the value from
    :rtype: int
    """
    max_entropies = sorted(entropies, reverse=True)[:sampling_weight]
    indexes = []

    for index, value in enumerate(entropies):
        if value in max_entropies:
            indexes.append(index)

    return random.choice(indexes)


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            From a results file with features, evaluates vulnerabilities using 
            supervised machine learning.
        '''
    )

    parser.add_argument(
        '--features',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='Features values to be evaluated'
    )

    parser.add_argument(
        '--vulnerable-versions',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='The file path with a list of vulnerable versions to be used in the active learning process'
    )

    parser.add_argument(
        '--results',
        type=argparse.FileType('w+'),
        default=sys.stdout,
        help='Path to store the results'
    )

    return parser.parse_args()


def main():
    config = process_arguments()

    print("Processing features from file {} with training versions {} ...".format(config.features,
                                                                                  config.vulnerable_versions))

    calculated_features = json.load(config.features)

    next_version = active_learning_prediction(calculated_features, config.vulnerable_versions)

    if calculated_features:
        json.dump(calculated_features, config.results, sort_keys=True, indent=4)

    print("\n\nNext version to be inserted in the training model: {}".format(next_version))


if __name__ == '__main__':
    main()
