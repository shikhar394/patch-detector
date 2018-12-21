import semantic_version as sv
import os
import re


class CheckVersion():
    def __init__(self, VersionRangeList, VersionToCheck):
        """
        Inputs 
        - a list of versions in str format from the file generated from generate_SNYK_vulnerabilities
        - Example: ["[3.2-alpha,3.3-beta-2)"] 
        - Splits up by the ','. Hence, every range exists in the following format
            - ['[3.2-alpha', '3.3-beta-2)']
        - Version to check in the intervals
        """
        self.RawVersionRange = VersionRangeList
        self.regexVersionPattern = r'(\d+(\.\d+|\_\d+|\-\d+){0,})(.*?)' #Identifies versions such as 1.2.3.4 | 1-2-3-4 | 1_2_3_4
        self.VersionRangeInput = [interval.lower().strip() for versionRange in VersionRangeList for interval in
                                    versionRange.split(',')]
        self.RawVersionToCheck = self.VersionToCheckPrefixHelper(VersionToCheck)  # Stores string
        self.VersionToCheck = sv.Version.coerce(self.RawVersionToCheck.lower())  # Stores Semantic Version object
        self.ManualInspectionFileName = os.path.join('experiments', 'vulnerabilities', 'ManualInspectionLog.txt')

    def FixVersionRegex(self, Version):
        """
        Regex currently messes up version such as v2-1.2.3.4-alpha1 since it captures 2-1.2.3.4 as the version token.
        This addresses that.
        """
        Delimiters = '-_.'
        DelimiterDict = {'-':0, '_':0, '.':0}
        for character in Version:
            if character in Delimiters:
                DelimiterDict[character] += 1

        DominantDelimiter = max(DelimiterDict.items(), key=operator.itemgetter(1))[0] #Finds the delimiter with the max count
        Delimiters = ''.join([i for i in Delimiters if i!=DominantDelimiter])
        for delimiter in Delimiters:
            Tokens = Version.split(delimiter)
            for Token in Tokens:
                if DominantDelimiter in Token:
                    Version = Token
            
        return Version
    
    def VersionToCheckPrefixHelper(self, versionToCheck):
        """
        Addresses version prefix for VersionToCheck parameter.
        Format: 'Jenkins-1.2.3'
        Splits from '-'
        Checks prefix, if true, recreates version by appending the prefix.
        """
        Version = re.search(self.regexVersionPattern, versionToCheck).group(
            1)  # Only select the first version group in case the suffix has another 1.2..
        
        VersionParts = versionToCheck.split(Version)
        Prefix = ''.join(i for i in VersionParts[0] if i.isalnum())
        Suffix = ''.join(i for i in VersionParts[1] if i.isalnum())
        return self.reconstructVersion(Version=Version, Prefix=Prefix, Suffix=Suffix)

    def VersionRangePrefixHelper(self, versionPoint):
        '''
        Accepts a range part from the version range. 
        ['Jenkins-1.2.3' or 'Jenkins-1.2.3] 
        Checks and recreates the version properly.
        '''
        VersionNumber = re.search(self.regexVersionPattern, versionPoint).group(
            1)  # Only select the first version group in case the suffix has another 1.2..
        VersionParts = versionPoint.split(VersionNumber)
        Prefix = ''.join(i for i in VersionParts[0] if i.isalnum())
        Suffix = ''.join(i for i in VersionParts[1] if i.isalnum())
        Bracket = [i for i in versionPoint if i in ('[]()')]

        if len(Bracket) > 1:
            with open(self.ManualInspectionFileName, 'a') as f:
                f.write("Strange version number" + str(versionPoint))
        else:
            Bracket = Bracket[0]

        FinalVersion = self.reconstructVersion(VersionNumber, Bracket=Bracket, Prefix=Prefix, Suffix=Suffix)
        return FinalVersion

    def reconstructVersion(self, Version, Bracket=None, Prefix=None, Suffix=None):
        VersionList = []
        #Standardizing versions
        if '_' in Version:
            Version = Version.split('_')
            Version = '.'.join(Version)
        elif "-" in Version:
            Version = Version.split('-')
            Version = '.'.join(Version)
        VersionList.append(Version)
        if Suffix:
            VersionList.append(Suffix)
        if Prefix:
            VersionList.append(Prefix)
        FinalVersion = '-'.join(VersionList)
        if Bracket:
            if Bracket in '([':
                FinalVersion = Bracket + FinalVersion
            else:
                FinalVersion = FinalVersion + Bracket
        return FinalVersion

    def CheckVersionInRange(self):
        """
        Iterates through the list in self.VersionRangeInput. 
        Treats the beginning and end of range as seperate versions and constructs Spec object.
        Checks the given range in the Spec object. Returns True, if found.
        Else, goes through the next set of ranges.
        """
        VersionRangeList = []
        for versionPoint in self.VersionRangeInput:
            if versionPoint[0] == '[' and versionPoint[-1] == ']':  # Checks single vulnerability
                if sv.Version.coerce(versionPoint[1:-1]) == self.VersionToCheck:
                    return True
            else:
                VersionRangeList.append(self.UnpackRange(versionPoint))  # Checks range of vulnerabilities
                if len(VersionRangeList) == 2:
                    if self.VersionToCheck in sv.Spec(','.join(VersionRangeList)):
                        return True
                    VersionRangeList = []
        return False

    def UnpackRange(self, versionPoint):
        """
        Takes the versions with the corresponding brackets and unpacks it as a mathematical notation
        This is done to comply with the semantic_version Spec object.
        """
        versionPoint = self.FixLonelyBracket(versionPoint)

        versionPoint = self.VersionRangePrefixHelper(versionPoint)

        if versionPoint[0] == '[':
            return '>=' + str(sv.Version.coerce(versionPoint[1:]))
        elif versionPoint[0] == '(':
            return '>' + str(sv.Version.coerce(versionPoint[1:]))
        elif versionPoint[-1] == ']':
            return '<=' + str(sv.Version.coerce(versionPoint[:-1]))
        elif versionPoint[-1] == ')':
            return '<' + str(sv.Version.coerce(versionPoint[:-1]))
        else:
            with open(self.ManualInspectionFileName, 'a') as f:
                f.write("Weird version range (part): " + versionPoint + "\nComplete version range: " + str(
                    self.RawVersionRange) + "\nVersion to check: " + str(self.RawVersionToCheck) + "\n\n")

    def FixLonelyBracket(self, versionPoint):
        """
        Addresses individual bracket from open ranges. 
        Example: Range: [,1.2.3]
        Then '[' would be the versionPoint.
        """
        if len(versionPoint) == 1:  # type of range: [,XXX] - gets only bracket : '['
            if versionPoint[0] == '[' or versionPoint[0] == '(':
                versionPoint = versionPoint[0] + '0'
            else:
                versionPoint = '10000000' + versionPoint[
                    0]  # Arbitrarily huge number to satisfy open ended upper limit.
        return versionPoint

    def __str__(self):
        PrintStatement = "Checking {} in {}".format(str(self.VersionToCheck), str(self.RawVersionRange))
        return PrintStatement


if __name__ == "__main__":
    """
    Test
    """
    VersionRange = ['[3.2-alpha,3.3-beta-2)']
    Versions = CheckVersion(VersionRange, '3.3-alpha')

    print("Checking {} in {}".format('3.3-alpha', str(VersionRange)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRange, '3.3-beta-3')

    print("Checking {} in {}".format('3.3-beta-3', str(VersionRange)))
    print(Versions.CheckVersionInRange() == False)

    VersionRange = ['[10.10.0], [,1.1.0-CR0-3), [1.1.0-CR1,1.1.0-CR3_1), \
      [1.1.0-CR4, 1.3.7-CR1_2), [1.4.0,1.4.2-CR4_1), \
      [1.5.0,1.5.4-CR6_2), [1.5.4-CR7,1.5.4-CR7_1], [1.5.5,1.5.7_9)']
    Versions = CheckVersion(VersionRange, '0.0.0.0.0.0')

    Versions = CheckVersion(VersionRange, '10.10.0')

    print("Checking {} in {}".format('10.10.0', str(VersionRange)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRange, '1.1.0-CR1')

    print("Checking {} in {}".format('1.1.0-CR1', str(VersionRange)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRange, '1.3.6-CR1')

    print("Checking {} in {}".format('1.3.6-CR1', str(VersionRange)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRange, '1.3.7-CR1_2')

    print("Checking {} in {}".format('1.3.7-CR1_2', str(VersionRange)))
    print(Versions.CheckVersionInRange() == False)

    VersionRangePrefix = ['[jenkins-1.2.3, prototype-1.7]']  # Adopted from the Jenkins github repo
    Versions = CheckVersion(VersionRangePrefix, 'jenkins-1.7')

    print("Checking {} in {}".format('jenkins-1.7', str(VersionRangePrefix)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRangePrefix, 'Jenkins-1.7')

    print("Checking {} in {}".format('Jenkins-1.7', str(VersionRangePrefix)))
    print(Versions.CheckVersionInRange() == True)

    Versions = CheckVersion(VersionRangePrefix, 'Protoype-1.8')

    print("Checking {} in {}".format('Protoype-1.8', str(VersionRangePrefix)))
    print(Versions.CheckVersionInRange() == False)

    VersionRangePrefix = ['[jenkins-1.2.3-alpha, prototype-1.7-beta]']  # Adopted from the Jenkins github repo
    Versions = CheckVersion(VersionRangePrefix, 'jenkins-1.7-beta')

    print("Checking {} in {}".format('jenkins-1.7-beta', str(VersionRangePrefix)))
    print(Versions.CheckVersionInRange() == True)

    VersionRangePrefix = ['[jenkins_1.2.3.alpha, prototype-1.7-beta]']  # Adopted from the Jenkins github repo
    Versions = CheckVersion(VersionRangePrefix, 'jenkins_1.7-beta')

    print("Checking {} in {}".format('jenkins_1.7.beta', str(VersionRangePrefix)))
    print(Versions.CheckVersionInRange() == True)
