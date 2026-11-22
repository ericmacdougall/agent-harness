"""Scoped ambient Sites metadata is admitted, then removed from owned Git."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import git_safety as safety
import integrate_local as integrate
import publish_feature as publish
import deliver

SCOPES = ('https://chatgpt.com/backend-api/codex/sites/git/',
          'https://chatgpt-staging.com/backend-api/codex/sites/git/')
KEYS = tuple(f'{section}.{scope}.{option}' for scope in SCOPES
             for section, option in (('credential', 'helper'), ('credential', 'useHttpPath'),
                                     ('http', 'proactiveAuth'), ('http', 'followRedirects')))


def family(keys=KEYS):
    result = {'GIT_CONFIG_COUNT': str(len(keys))}
    for index, key in enumerate(keys):
        result[f'GIT_CONFIG_KEY_{index}'] = key
        result[f'GIT_CONFIG_VALUE_{index}'] = 'synthetic ignored value'
    return result


def unsupported(environment):
    # Baseline control uses the existing admission predicate, so the positive
    # fails on behavior rather than merely on a missing import.
    validator = getattr(safety, 'unsupported_git_environment', None)
    if validator is None:
        return any(name.startswith('GIT_') and name not in integrate.ALLOWED_GIT_ENV for name in environment)
    return validator(environment, integrate.ALLOWED_GIT_ENV)


class NoValueReads(dict):
    def __getitem__(self, key):
        if key.startswith('GIT_CONFIG_VALUE_'):
            raise AssertionError('indexed values must not be inspected')
        return super().__getitem__(key)

    def get(self, key, default=None):
        return self[key] if key in self else default

    def items(self):
        raise AssertionError('whole environment value iteration is forbidden')

    def values(self):
        raise AssertionError('whole environment value iteration is forbidden')


class SitesEnvironment(unittest.TestCase):
    def test_complete_literal_families_and_zero_are_admitted_without_value_reads(self):
        for keys in ((), KEYS, (KEYS[0],), KEYS * 2, (KEYS[0],) * 20):
            with self.subTest(count=len(keys)):
                self.assertFalse(unsupported(NoValueReads(family(keys))))

    def test_count_holes_extras_and_noncanonical_indices_are_rejected(self):
        for count in ('', '-1', '+1', '01', ' 1', '1 ', '1.0', '21', '999999999999999999999'):
            value = family((KEYS[0],))
            value['GIT_CONFIG_COUNT'] = count
            self.assertTrue(unsupported(NoValueReads(value)))
        for key in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0'):
            value = family((KEYS[0],))
            del value[key]
            self.assertTrue(unsupported(NoValueReads(value)))
        for key in ('GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'GIT_CONFIG_KEY_00',
                    'GIT_CONFIG_VALUE_-1', 'GIT_CONFIG_KEY_other', 'GIT_CONFIG_PARAMETERS'):
            value = family((KEYS[0],))
            value[key] = 'irrelevant'
            self.assertTrue(unsupported(NoValueReads(value)))

    def test_scope_key_and_routing_changes_are_rejected(self):
        for key in ('credential.helper', 'include.path', 'url.fake.insteadOf',
                    KEYS[0].replace('chatgpt.com', 'github.com'),
                    KEYS[0].replace('chatgpt.com', 'chatgpt.com.evil.invalid'),
                    KEYS[0].replace('https://', 'http://'), KEYS[0].upper(),
                    KEYS[0].replace('/sites/git/', '/sites/git'),
                    KEYS[0].replace('/sites/git/', '/sites/git/../'),
                    KEYS[0].replace('chatgpt.com', 'user@chatgpt.com'),
                    KEYS[0].replace('chatgpt.com', 'chatgpt.com:443')):
            self.assertTrue(unsupported(NoValueReads(family((key,)))))
        for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG',
                     'GIT_CONFIG_SYSTEM', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
            value = family()
            value[name] = ''
            self.assertTrue(unsupported(NoValueReads(value)))
        self.assertFalse(unsupported({'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}))

    def test_owned_git_dispatch_strips_scoped_helper_and_never_executes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / 'helper-ran'
            script = root / 'synthetic-helper.py'
            script.write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n')
            inherited = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
            inherited.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
            injected = family((KEYS[0], KEYS[1]))
            injected['GIT_CONFIG_VALUE_0'] = '!' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(script))
            injected['GIT_CONFIG_VALUE_1'] = 'true'
            inherited.update(injected)
            request = 'url=' + SCOPES[0] + '\n\n'
            # Negative control: real Git executes the synthetic helper if this
            # exact scoped configuration leaks into the child.
            subprocess.run(['git', 'credential', 'fill'], input=request, text=True,
                           env=inherited, cwd=root, capture_output=True, timeout=10)
            self.assertTrue(sentinel.exists(), 'credential leak control did not exercise the helper')
            sentinel.unlink()
            request_script = root / 'credential-request.py'
            request_script.write_text('import subprocess\nsubprocess.run(["git", "credential", "fill"], '
                                      'input=' + repr(request) + ', text=True, capture_output=True, timeout=10)\n')
            alias = 'alias.sites-probe=!' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(request_script))
            # An actual Git alias lets the no-stdin delivery dispatcher exercise
            # credential lookup without contacting a network service.
            subprocess.run(['git', '-c', alias, 'sites-probe'], env=inherited,
                           cwd=root, capture_output=True, timeout=10)
            self.assertTrue(sentinel.exists(), 'delivery dispatch leak control did not exercise the helper')
            sentinel.unlink()
            with patch.dict(os.environ, inherited, clear=True):
                self.assertFalse(unsupported(NoValueReads(injected)))
                result = publish.run_git(root, 'credential', 'fill', input=request, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(sentinel.exists())
                config = integrate.run_git_nohooks(root, 'config', '--get-regexp', r'^(credential|http)\.', timeout=10)
                self.assertEqual(config.returncode, 1)
                self.assertEqual(config.stdout, '')
                code, _ = deliver.git(root, '-c', alias, 'sites-probe', timeout=10)
                self.assertEqual(code, 0)
                self.assertFalse(sentinel.exists())
