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
