import unittest
import sqlite3
from vuldb import Checker, DB, ALLOW_SEVERITY


class vuldbTest(unittest.TestCase):

    def setUp(self) -> None:
        self.db = sqlite3.connect(DB)

    def tearDown(self) -> None:
        if hasattr(self, 'db'):
            self.db.close()

    def test_get_dependencies_list(self):
        deps = {
            'Name1': {
                'name':     'Name1',
                'version':  'version1',
                'from':     ['Name1@version1'],
                'dependencies': {
                    'Name2': {
                        'name':     'Name2',
                        'version':  'version2',
                        'from':     ['Name1@version1', 'Name2@version2'],
                        'dependencies': {
                            'Name3': {
                                'name':     'Name3',
                                'version':  'version3',
                                'from':     ['Name1@version1', 'Name2@version2', 'Name3@version3'],
                                'dependencies': {}
                            }
                        }
                    }
                }
            }
        }

        expect = [{
            'name':     'Name1',
            'version':  'version1',
            'from':     ['Name1@version1'],
            'root':     ''
        }, {
            'name':     'Name2',
            'version':  'version2',
            'from':     ['Name1@version1', 'Name2@version2'],
            'root':     'name1'
        }, {
            'name':     'Name3',
            'version':  'version3',
            'from':     ['Name1@version1', 'Name2@version2', 'Name3@version3'],
            'root':     'name2'
        }]
        result = list(Checker._get_dependencies_list(deps))
        self.assertEqual(expect, result)

    def test_get_vulrules(self):
        checker = Checker(self.db, 'Maven', {}, 'java', 'High')
        ruleset = checker.vulrules

        for name, rules in ruleset.items():
            for rule in rules:
                self.assertEqual(rule['severity'], 'High')
                self.assertIsInstance(rule['vul_version_fr'], str)
                self.assertIsInstance(rule['vul_version_fr'], str)
                self.assertIsInstance(rule['target_version'], list)

        checker = Checker(self.db, 'Maven', {}, 'java', 'Low')
        ruleset = checker.vulrules
        for name, rules in ruleset.items():
            for rule in rules:
                self.assertIn(rule['severity'], ALLOW_SEVERITY)

        checker = Checker(self.db, 'foo', {}, 'java', 'Low')
        ruleset = checker.vulrules
        self.assertEqual(ruleset, {})

    def test_java_version_in(self):
        checker = Checker(self.db, 'Maven', {}, 'java', 'High')

        self.assertTrue(checker._version_in(
            '2.6.0', '1.3.0', '2.9.0'
        ))

        self.assertTrue(checker._version_in(
            '0.2.0-incubating', '0.1.0-incubating', '0.3.0-incubating'
        ))

        self.assertTrue(checker._version_in(
            '2.9.10.1', '2.0.0', '2.9.10.1'
        ))

        self.assertFalse(checker._version_in(
            '2.16', '2.0', '2.9'
        ))

    def test_other_version_in(self):
        checker = Checker(self.db, 'Composer', {}, 'php', 'High')

        self.assertTrue(checker._version_in(
            '1.3', '1.0', '2.0'
        ))

        self.assertTrue(checker._version_in(
            'v1.3', '1.0', '2.0'
        ))

        self.assertFalse(checker._version_in(
            '1.3', 'v1.0', 'v1.2'
        ))

        self.assertTrue(checker._version_in(
            '1.3.rc1', '1.0', '1.3'
        ))

    def test_target_version_compare(self):
        checker = Checker(self.db, 'Composer', {}, 'php', 'High')

        self.assertTrue(checker._target_version_compare(
            {'target_version': ['2.6.6']},
            {'target_version': ['2.6.5']},
        ))

        self.assertTrue(checker._target_version_compare(
            {'target_version': ['4.0']},
            {'target_version': ['2.6.5']},
        ))

    def test_get_vuln(self):
        checker = Checker(self.db, 'Maven', {}, 'java', 'High')
        vuln = checker.get_vuln('com.alibaba:fastjson', '1.2.33')
        self.assertEqual(vuln['title'], 'Deserialization of Untrusted Data')
        self.assertEqual(vuln['severity'], 'High')
        self.assertEqual(vuln['target_version'], ['1.2.69'])

    def test_check_vuln(self):
        dependencies = {
            'com.alibaba:fastjson': {
                'name': 'com.alibaba:fastjson',
                'version': '1.2.33',
                'from': ['com.study:example@1.0.0', 'com.alibaba:fastjson@1.2.33'],
                'dependencies': {
                    'com.study:inner': {
                        'name': 'com.study:inner',
                        'version': '1.2.3',
                        'from': ['com.study:example@1.0.0', 'com.alibaba:fastjson@1.2.33', 'com.study:inner@1.2.3'],
                        'dependencies': {}
                    }
                }
            },
            'com.study:another': {
                'name': 'com.study:another',
                'version': '1.2.33',
                'from': ['com.study:example@1.0.0', 'com.study:another@1.2.33'],
                'dependencies': {}
            }
        }

        expect = {
            'ok': False,
            'dependencyCount': 2,
            'vulnerabilities': [{
                'packageName':      'com.alibaba:fastjson',
                'version':          '1.2.33',
                'from':             ['com.study:example@1.0.0', 'com.alibaba:fastjson@1.2.33'],
                'severity':         'High',
                'target_version':   ['1.2.69'],
                'cve':              'CWE-502',
                'title':            'Deserialization of Untrusted Data',
            }]
        }
        checker = Checker(self.db, 'Maven', dependencies, 'java', 'High')
        result = checker.check_vuln()
        self.assertEqual(expect, result)


        dependencies = {
            'com.study:example': {
                'name': 'com.study:example',
                'version': '1.2.0',
                'from': ['com.study:parent@1.0.0', 'com.study:example@1.2.0'],
                'dependencies': {}
            }
        }
        expect = {
            'ok': True,
            'dependencyCount': 1,
            'vulnerabilities': []
        }
        checker = Checker(self.db, 'Maven', dependencies, 'java', 'High')
        result = checker.check_vuln()
        self.assertEqual(expect, result)


if __name__ == '__main__':
    unittest.main()
