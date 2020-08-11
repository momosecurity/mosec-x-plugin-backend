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
import json
import os
from collections import defaultdict
from pkg_resources import parse_version
from f8a_version_comparator.comparable_version import ComparableVersion

DB = os.path.join(os.path.dirname(__file__), 'vuldata.sqlite3')
ALLOW_SEVERITY = ['High', 'Medium', 'Low']


class Checker(object):

    def __init__(self, db: object, lib_type: str, dependencies: dict, language: str, severity: str):
        self.db = db
        self.lib_type = lib_type
        self.dependencies = list(self._get_dependencies_list(dependencies))
        self.language = language
        self.severity = severity
        self.vulrules = self._get_vulrules(lib_type, severity)
        self.ver = get_version_tool(self.language)

    @classmethod
    def _get_dependencies_list(cls, dependencies: dict, root=''):
        for name, deps in dependencies.items():
            yield {
                'name': name,
                'version': deps.get('version'),
                'from': deps.get('from', []),
                'root': root
            }
            if isinstance(deps.get('dependencies'), dict):
                for v in cls._get_dependencies_list(deps['dependencies'], name.lower()):
                    yield v

    def _get_vulrules(self, lib_type: str, severity: str) -> dict:
        """
        :param lib_type: 构建工具类型(Maven, Composer, pip, npm等)
        :param severity: 威胁级别(High, Medium, Low)
        :return: {
            lower('name'): [{
                'title':    '漏洞描述',
                'name':     '组件名称',
                'severity': '漏洞威胁级别',
                'cve':      'cve/cwe编号',
                'vul_version_fr':   x,
                'vul_version_to':   y,
                'target_version':   ['v1', 'v2']
            }, {
                ...
            }],
            lower('name2'): [{
                ...
            }]
        }
        """
        query_args = []
        if severity == 'High':
            query_severity = "?"
            query_args.append('High')
        elif severity == 'Medium':
            query_severity = "?, ?"
            query_args.extend(['High', 'Medium'])
        else:
            query_severity = "?, ?, ?"
            query_args.extend(['High', 'Medium', 'Low'])

        query_args.append(lib_type)
        rules = query_db(self.db,
                         "SELECT title, name, severity, cve, vul_version_fr, vul_version_to, target_version"
                         " FROM vulrules"
                         " WHERE severity in (" +query_severity +")"
                         "     AND type = ?",
                         query_args)
        result = defaultdict(list)
        for rule in rules:
            rule['target_version'] = json.loads(rule['target_version'])
            result[rule['name'].lower()].append(rule)
        return result

    def _version_in(self, version: str, vul_version_fr: str, vul_version_to: str) -> bool:
        return self.ver(vul_version_fr) <= self.ver(version) <= self.ver(vul_version_to)

    def _target_version_compare(self, src: dict, dst: dict) -> bool:
        src_max_v = max(src['target_version'], key=lambda x: self.ver(x))
        dst_max_v = max(dst['target_version'], key=lambda x: self.ver(x))
        return self.ver(src_max_v) > self.ver(dst_max_v)

    def get_vuln(self, name: str, version: str) -> dict:
        rules = self.vulrules.get(name.lower(), {})
        if not rules:
            return {}

        max_target_version_vuln = {}
        for rule in rules:
            if not self._version_in(version, rule['vul_version_fr'], rule['vul_version_to']):
                continue
            if not max_target_version_vuln:
                max_target_version_vuln = rule
                continue
            elif self._target_version_compare(rule, max_target_version_vuln):
                max_target_version_vuln = rule
        return max_target_version_vuln

    def check_vuln(self) -> dict:
        result = {
            'ok': True,
            'dependencyCount': 0,
            'vulnerabilities': []
        }

        roots = set()
        for dep in self.dependencies:
            if dep['root'] in roots:
                roots.add(dep['name'])
                continue
            result['dependencyCount'] += 1

            vuln = self.get_vuln(dep['name'], dep['version'])
            if vuln:
                roots.add(dep['name'])
                result['vulnerabilities'].append({
                    'packageName':      dep['name'],
                    'version':          dep['version'],
                    'from':             dep['from'],
                    'severity':         vuln['severity'],
                    'target_version':   vuln['target_version'],
                    'cve':              vuln['cve'],
                    'title':            vuln['title'],
                })
        result['ok'] = not bool(result['vulnerabilities'])
        return result


def get_version_tool(language: str):
    if language == 'java':
        return ComparableVersion
    else:
        return parse_version


def query_db(db: object, query: str, args=(), one=False):
    cur = db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv
