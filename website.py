"""
Copyright 2020 momosecurity.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import sqlite3
from flask import Flask, jsonify, request, g
from vuldb import DB, Checker, ALLOW_SEVERITY

app = Flask(__name__)


@app.before_request
def before_request():
    g.db = sqlite3.connect(DB)


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/api/plugin', methods=['POST'])
def api_mosec():
    try:
        data = request.json
        lib_type = data['type']
        dependencies = data['dependencies']
        language = data['language']
        severity = data['severityLevel'].capitalize()
        if severity not in ALLOW_SEVERITY:
            severity = 'High'
    except Exception as e:
        return jsonify({'msg': 'Post Data Error'}), 400

    try:
        res = Checker(g.db, lib_type, dependencies, language, severity).check_vuln()
    except Exception as e:
        return jsonify({'msg': 'Server Error'}), 500

    return jsonify(res)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=9000)
