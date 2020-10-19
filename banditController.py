import os, sys, subprocess, random
from github import Github

NUMBER_LIBS_TO_ANALYZE = 5
REPOSITORY_NAME = 'the-maux/SecuCI'
PATH_SITE_PACKAGE = ''


def startBandit(libName):
    global PATH_SITE_PACKAGE
    #    First get site-package
    cmd = f'python3 -c "import {libName} as lib; print(lib.__path__)"'
    print(f'\t$> {cmd}')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()
    process.wait()
    output = output.decode('utf-8').replace("\n", '')
    if output:
        PATH_SITE_PACKAGE = output[2:-2].replace(libName, '')
        cmd = f"bandit -r  {PATH_SITE_PACKAGE}{libName}"
        # Run bandit commande and save the output in a variable
        print(f"$> {cmd}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (output, err) = process.communicate()
        process.wait()
        output = output.decode('utf-8')
    return output, err


def parseOutputOfBandit(banditrapport):
    """ Parse the output of bandit rapport to build a list of issue dict """
    rapport = ''
    if banditrapport:
        try:
            filteredLines = ['[main]', 'Run started', 'Test results:']
            for line in banditrapport.split("\n"):
                if not any(substring in line for substring in filteredLines):
                    rapport += line + '\n'
            issues = rapport.split('Code scanned:')[0]
            resume = f'Code scanned: {rapport.split("Code scanned:")[1]}'
            listOfIssue = list()
            for issue in issues.split('--------------------------------------------------\n'):
                issue = issue[1:] if issue[0] == '\n' else issue
                if issue:
                    issueTmp = issue.split('\n')
                    if issueTmp[0]:
                        issueData = dict(Issue=issueTmp[0].replace('>> Issue: ', ''),
                                         Severity=issueTmp[1].split('Confidence:')[0].replace('Severity: ', ''),
                                         Confidence=issueTmp[1].split('Confidence:')[1].replace('Confidence: ', ''),
                                         Location=issueTmp[2].replace('\tLocation: ', '').replace(PATH_SITE_PACKAGE, ''),
                                         Code=[x.strip().replace('\t', ' ') for x in issueTmp[4:] if
                                               x.strip()])  # clean string
                        listOfIssue.append(issueData)
            return listOfIssue, resume
        except:
            print("(ERROR) while parsing dump of bandit")
            print(f'the Dump is here[{banditrapport}]')
    else:
        print("\n[ERROR] Bandit rapport is empty, wtf ?\n")
    return None, None


def createIssue(libToParse, listOfIssue, labels, resume):
    github_token = os.environ['GITHUB_PASSWD']
    repository = Github(github_token).get_repo(REPOSITORY_NAME)
    print(f'Analyze of {libToParse} with {resume[0]}')
    response = repository.create_issue(title=f'Analyze of {libToParse}', labels=labels, body=resume)
    print(f'New issue created:{response}')
    for issue in listOfIssue:
        comment = f"""
### {issue['Issue']}
| Severity: {issue['Severity']} | Confidence: {issue['Confidence']} | 
| -------- | -------- |

##### {issue['Location']}
``` python
"""
        for line in issue['Code']:
            comment += line + '\n'
        comment += '```'
        response.create_comment(comment)


def buildResume(resume):
    data = dict(Severity=dict(), Confidence=dict())
    resume = resume.split('Run metrics:')[1]
    severity = resume.split('Total issues (by confidence):')[0].replace('Total issues (by severity):', '')
    confidence = resume.split('Total issues (by confidence):')[1].replace('Total issues (by confidence):', '')

    for line in severity.split('\n'):
        if 'Undefined:' in line:
            data['Severity']['Undefined'] = line.replace('Undefined:', '')
        if 'Low:' in line:
            data['Severity']['Low'] = line.replace('Low:', '')
        if 'Medium:' in line:
            data['Severity']['Medium'] = line.replace('Medium:', '')
        if 'High:' in line:
            data['Severity']['High'] = line.replace('High:', '')
    for line in confidence.split('\n'):
        if 'Undefined:' in line:
            data['Confidence']['Undefined'] = line.replace('Undefined:', '')
        if 'Low:' in line:
            data['Confidence']['Low'] = line.replace('Low:', '')
        if 'Medium:' in line:
            data['Confidence']['Medium'] = line.replace('Medium:', '')
        if 'High:' in line:
            data['Confidence']['High'] = line.replace('High:', '')
    GlobalIndications = list()
    if data['Severity']['High'] != '0.0' or data['Confidence']['High'] != '0.0':
        GlobalIndications.append('HIGH')
    if data['Severity']['Medium'] != '0.0' or data['Confidence']['Medium'] != '0.0':
        GlobalIndications.append('MEDIUM')
    if data['Severity']['Low'] != '0.0' or data['Confidence']['Low'] != '0.0':
        GlobalIndications.append('LOW')
    return GlobalIndications, f"""
# Resultat
|    /          |    Severity | Confidence | 
| ------------  | ------------------|-------------------|
|  Undefined    |  {data['Severity']['Undefined']}               |  {data['Confidence']['Undefined']}              |
|  Low          |  {data['Severity']['Low']}               |  {data['Confidence']['Low']}              |
|  Medium       |  {data['Severity']['Medium']}               |  {data['Confidence']['Medium']}              |
|  High         |  {data['Severity']['High']}               |  {data['Confidence']['High']}              |

Files skipped (0):
"""


def analyzeLibs():
    """ Get the NUMBER_LIBS_TO_ANALYZE last lib on requirements.txt """
    file = open('requirements-pentest.txt', 'r')
    libs = [line.replace("\n", "") for line in file.readlines()]
    file.close()
    for libToParse in libs[-NUMBER_LIBS_TO_ANALYZE:]:
        print(f'Starting bandit on {libToParse}')
        stdout, stderr = startBandit(libToParse)
        listOfIssue, resume = parseOutputOfBandit(stdout)
        if listOfIssue is not None:
            labels, resume = buildResume(resume)
            createIssue(libToParse, listOfIssue, labels, resume)


def chooseTheRightLibToAnalyse():
    import requests
    # TODO: check if duplicate report on repo first
    ready = False
    listOfLibs = list()
    pypiApiresponse = requests.get('https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json').json()
    while not ready:
        listOfLibs = [lib['project'] for lib in random.choices(pypiApiresponse['rows'], k=NUMBER_LIBS_TO_ANALYZE)]
        if not any('-' in lib for lib in listOfLibs):  # '-' is causing bug...
            ready = True
    return listOfLibs


def prepareTheJob():  # TODO check on repo that lib is not already analyzed
    """ Add random popular lib to requirements.txt """
    file = open("requirements-pentest.txt", "a+")
    listOfLibs = chooseTheRightLibToAnalyse()
    print(f'Target are :{listOfLibs}, let\'s install dependencies')
    for lib in listOfLibs:
        file.write(lib + '\n')
    file.close()


if __name__ == '__main__':
    if sys.argv[1] == '--configure':
        print('\n\n --------- BANDIT  STARTING ------------\n')
        prepareTheJob()
    elif sys.argv[1] == '--start':
        analyzeLibs()
        print('\n\n --------- BANDIT     ENDING  ------------\n')
