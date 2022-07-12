# written by mohlcyber - 12.07.2022
# Flask Application to simulate Trellix ATD|TIS APIs to integrate various solutions with DoD|TDaaS

import base64
import secrets
import json
import requests
import sys
import os
import hashlib

from flask import Flask, request, Response

app = Flask(__name__)

# Random username and password. Needs to be the same as inside the TIE server policy or MWG rule set.
ATD_USER = 'username'
ATD_PW = 'password'

# Log into DoD > Settings > Key Management > Create new Authorization Key
DOD_API = ''

CREDS = base64.b64encode((ATD_USER + ":" + ATD_PW).encode())

SESSION_TOKEN = secrets.token_hex(13)
SESSION_USER_ID = "1"
SESSION_CREDS = base64.b64encode((SESSION_TOKEN + ":" + SESSION_USER_ID).encode())


class DOD():
    def __init__(self):
        self.base_url = 'https://feapi.marketplace.apps.fireeye.com'

        self.session = requests.Session()
        self.session.headers = {
            'feye-auth-key': DOD_API
        }

    def submit_file(self, fname, fbytes):
        files = {
            'file': (fname, fbytes)
        }

        data = {
            'screenshot': True,
            'video': True,
            'file_extraction': True,
            'memory_dump': True,
            'pcap': True
        }

        res = self.session.post(self.base_url + '/files', data=data, files=files)

        if res.ok:
            report_id = res.json()['report_id']
            return report_id
        else:
            print('Something went wrong. {0} - {1}'.format(res.status_code, res.text))
            sys.exit()

    def get_report(self, report_id):
        param = {
            'extended': True
        }
        res = self.session.get('{0}/reports/{1}'.format(self.base_url, report_id), params=param)

        if res.ok:
            return res.json()
        else:
            print('Something went wrong')
            sys.exit()

    def prep_report(self, res):
        # Parse the right objects from DOD response
        filename = res['name']
        md5 = res['md5']
        sha1 = res['sha1']
        sha256 = res['sha256']
        size = res['size']
        report_id = res['report_id']

        # Prep ATD Report response
        file = open('report.json').read()
        report = json.loads(file)

        report['Summary']['JobId'] = report_id
        report['Summary']['TaskId'] = report_id

        report['Summary']['Files'][0]['Name'] = filename
        report['Summary']['Files'][0]['Md5'] = md5
        report['Summary']['Files'][0]['Sha1'] = sha1
        report['Summary']['Files'][0]['Sha256'] = sha256
        report['Summary']['Files'][0]['Processes'][0]['Name'] = filename
        report['Summary']['Files'][0]['Processes'][0]['Sha256'] = sha256

        report['Summary']['Process'][0]['Name'] = filename
        report['Summary']['Processes'][0]['Name'] = filename

        report['Summary']['Subject']['Name'] = filename
        report['Summary']['Subject']['md5'] = md5
        report['Summary']['Subject']['sha-1'] = sha1
        report['Summary']['Subject']['sha-256'] = sha256
        report['Summary']['Subject']['size'] = size

        i = 0
        for sign_name in res['signature_name']:
            stats = {
                'Category': sign_name,
                'ID': i,
                'Severity': '-1'
            }
            i += 1
            report['Summary']['Stats'].append(stats)

        if res['verdict'] == 'MALICIOUS':
            report['Summary']['Process'][0]['Severity'] = '5'
            for selector in report['Summary']['Selectors']:
                if selector['Engine'] == 'Sandbox':
                   selector['Severity'] = '5'

            report['Summary']['Stats'][0]['Severity'] = '5'
            report['Summary']['Verdict']['Severity'] = '5'

        return report


@app.route('/php/session.php', methods=['GET'])
def login():
    if request.headers.get('VE-SDK-API'):
        if request.headers.get("VE-SDK-API") == CREDS.decode():
            payload = {
                "success": True,
                "results": {
                    "session": SESSION_TOKEN,
                    "userId": "1",
                    "isAdmin": "1"
                },
            }

            res = Response(status=200)
            res.headers['Content-type'] = 'application/json'
            res.data = json.dumps(payload)

            return res

        else:
            res = Response(status=401)
            res.data = 'Not authorized'
            return res


@app.route('/php/samplestatus.php', methods=['GET'])
def status():
    params = request.args
    if 'jobId' in params:
        qid = params['jobId']
        resp = DOD().get_report(qid)

        status = resp['overall_status']
        if status == 'DONE':
            status_id = 5
        else:
            status_id = 3

        payload = {
            'success': True,
            'status': status_id,
            'allEngineState': 1
        }
    elif 'iTaskId' in params:
        qid = params['iTaskId']
        resp = DOD().get_report(qid)

        status = resp['overall_status']
        if status == 'DONE':
            istate = 1
        else:
            istate = 3

        payload = {
            "results":
                {
                    "istate": istate,
                    "jobid": qid,
                    "taskid": qid
                },
            "success": True
        }

    else:
        raise Exception

    res = Response(status=200)
    res.headers['Content-type'] = 'application/json'
    res.data = json.dumps(payload)

    return res


@app.route('/php/fileupload.php', methods=['POST'])
def submit():
    file = request.files['amas_filename']
    filename = file.filename
    file.save(os.path.join(os.getcwd(), filename))

    data = open(os.path.join(os.getcwd(), filename), 'rb').read()

    dod = DOD()
    reportid = dod.submit_file(filename, data)

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    os.remove(os.path.join(os.getcwd(), filename))

    payload = {
        "success": True,
        "subId": reportid,
        "fileId": "",
        "filesWait": 0,
        "estimatedTime": 0,
        "results": [
            {
                "taskId": reportid,
                "file": filename,
                "submitType": "0",
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "cache": 0
            }
        ]
    }

    res = Response(status=200)
    res.headers['Content-type'] = 'application/json'
    res.data = json.dumps(payload)

    return res


@app.route('/php/showreport.php', methods=['GET', 'POST'])
def report():
    dod = DOD()
    params = request.args

    if 'jobId' in params:
        qid = params['jobId']
    elif 'iTaskId' in params:
        qid = params['iTaskId']
    else:
        raise Exception

    resp = dod.get_report(qid)
    report = dod.prep_report(resp)
    res = Response(status=200)
    res.headers['Content-type'] = 'application/json'
    res.data = json.dumps(report)

    return res


@app.route('/php/session.php', methods=['DELETE'])
def logout():
    res = Response(status=200)
    res.headers['Content-type'] = 'application/json'

    return res