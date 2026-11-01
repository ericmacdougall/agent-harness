import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


RESCUE = Path(__file__).resolve().parents[1] / 'harness/hooks/rescue.py'
# Outer test watchdogs, not product deadlines. Validation runs several Git reads.
STANDARD_HELPER_WATCHDOG_SECONDS = 30
FUNCTIONAL_HELPER_WATCHDOG_SECONDS = 90
sys.path.insert(0, str(RESCUE.parent))
SPEC = importlib.util.spec_from_file_location('rescue_under_test', RESCUE)
rescue = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rescue)


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


class RescueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'feat/rescue')
        git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        git(self.repo, 'config', 'user.name', 'Fixture')
        (self.repo / 'app.txt').write_text('baseline\n')
        git(self.repo, 'add', 'app.txt')
        git(self.repo, 'commit', '-qm', 'baseline')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        self.packet = self.root / 'packet.md'
        self.packet.write_text('A disposable rescue packet.')
        self.output = self.root / 'report.json'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.fake('codex', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CODEX_PROMPT')
if capture: Path(capture).write_text(prompt)
action = os.environ.get('CODEX_ACTION', '')
if action: Path('app.txt').write_text(action + '\\n')
outside = os.environ.get('CODEX_LINK_OUTSIDE')
if outside:
    Path('app.txt').unlink()
    os.link(outside, 'app.txt')
if os.environ.get('CODEX_COMMIT'):
    import subprocess
    subprocess.run(['git', 'add', 'app.txt'], check=True)
    subprocess.run(['git', 'commit', '-qm', 'model commit'], check=True)
    if os.environ.get('CODEX_DIRTY_AFTER_COMMIT'):
        Path('app.txt').write_text('new dirty edit\\n')
    if os.environ.get('CODEX_STAGE_AFTER_COMMIT'):
        Path('app.txt').write_text('staged after commit\\n')
        subprocess.run(['git', 'add', 'app.txt'], check=True)
if os.environ.get('CODEX_SET_IGNORECASE') or os.environ.get('CODEX_ADD_CASE_VARIANT'):
    import subprocess
    subprocess.run(['git', 'config', 'core.ignoreCase', 'true'], check=True)
if os.environ.get('CODEX_ADD_CASE_VARIANT'):
    Path('APP.TXT').write_text('distinct addition\\n')
reset = os.environ.get('CODEX_RESET_TO')
if reset:
    import subprocess
    if os.environ.get('CODEX_FORGE_GRAPH_PARENT'):
        subprocess.run(['git', 'branch', 'keep-approved-base'], check=True)
    subprocess.run(['git', 'reset', '--hard', '-q', reset], check=True)
    if os.environ.get('CODEX_DIVERGE'):
        subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'sibling commit'], check=True)
    if os.environ.get('CODEX_DIRTY_AFTER_RESET'):
        Path('app.txt').write_text('unfinished after reset\\n')
    graft_base = os.environ.get('CODEX_GRAFT_BASE')
    if graft_base:
        graft = Path(subprocess.run(['git', 'rev-parse', '--git-path', 'info/grafts'],
                                    capture_output=True, text=True, check=True).stdout.strip())
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text(graft_base + '\\n' + reset + ' ' + graft_base + '\\n')
if os.environ.get('CODEX_GRAFT_ONLY'):
    import subprocess
    graft = Path(subprocess.run(['git', 'rev-parse', '--git-path', 'info/grafts'],
                                capture_output=True, text=True, check=True).stdout.strip())
    graft.parent.mkdir(parents=True, exist_ok=True)
    graft.write_text('# synthetic graft marker\\n')
if os.environ.get('CODEX_SWITCH_BRANCH'):
    import subprocess
    subprocess.run(['git', 'switch', '-q', '-c', 'feat/wrong'], check=True)
    subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'wrong branch'], check=True)
if os.environ.get('CODEX_LOCAL_FILTER'):
    import shlex, subprocess
    marker = os.environ['CODEX_LOCAL_FILTER']
    subprocess.run(['git', 'config', 'filter.fixture.clean',
                    "sh -c 'touch " + shlex.quote(marker) + "; cat'"], check=True)
    Path('app.txt').write_text('updated\\n')
if os.environ.get('CODEX_FORGE_GRAPH_PARENT') or os.environ.get('CODEX_FORGE_GRAPH_TREE'):
    import hashlib, subprocess
    subprocess.run(['git', 'commit-graph', 'write', '--reachable'], check=True)
    graph_path = subprocess.run(['git', 'rev-parse', '--git-path',
                                 'objects/info/commit-graph'],
                                capture_output=True, text=True, check=True).stdout.strip()
    graph = Path(graph_path)
    if not graph.is_absolute():
        graph = Path.cwd() / graph
    data = bytearray(graph.read_bytes())
    hash_size = {1: 20, 2: 32}[data[5]]
    chunks = {bytes(data[8 + i * 12:12 + i * 12]):
              int.from_bytes(data[12 + i * 12:20 + i * 12], 'big')
              for i in range(data[6])}
    count = int.from_bytes(data[chunks[b'OIDF'] + 1020:chunks[b'OIDF'] + 1024], 'big')
    oids = [data[chunks[b'OIDL'] + i * hash_size:
                 chunks[b'OIDL'] + (i + 1) * hash_size].hex() for i in range(count)]
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True,
                          text=True, check=True).stdout.strip()
    entry = chunks[b'CDAT'] + oids.index(head) * (hash_size + 16)
    parent = os.environ.get('CODEX_FORGE_GRAPH_PARENT')
    if parent:
        data[entry + hash_size:entry + hash_size + 4] = oids.index(parent).to_bytes(4, 'big')
    else:
        tree = subprocess.run(['git', 'write-tree'], capture_output=True,
                              text=True, check=True).stdout.strip()
        data[entry:entry + hash_size] = bytes.fromhex(tree)
    digest = hashlib.sha1 if hash_size == 20 else hashlib.sha256
    data[-hash_size:] = digest(data[:-hash_size]).digest()
    graph.chmod(0o600)
    graph.write_bytes(data)
if os.environ.get('CODEX_REDIRECT_GITDIR') or os.environ.get('CODEX_REDIRECT_COMMON_DIR'):
    import subprocess
    primary = os.environ['CODEX_PRIMARY_REPO']
    shadow = os.environ['CODEX_SHADOW_REPO']
    branch = subprocess.run(['git', 'branch', '--show-current'], capture_output=True,
                            text=True, check=True).stdout.strip()
    subprocess.run(['git', 'clone', '-q', '--branch', branch, primary, shadow], check=True)
    if not os.environ.get('CODEX_SHADOW_NO_COMMIT'):
        subprocess.run(['git', '-C', shadow, '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid',
                        'commit', '--allow-empty', '-qm', 'shadow descendant'], check=True)
    if os.environ.get('CODEX_REDIRECT_GITDIR'):
        Path('.git').write_text('gitdir: ' + str(Path(shadow) / '.git') + chr(10))
    else:
        gitdir = subprocess.run(['git', 'rev-parse', '--absolute-git-dir'],
                                capture_output=True, text=True, check=True).stdout.strip()
        (Path(gitdir) / 'commondir').write_text(str(Path(shadow) / '.git') + chr(10))
if os.environ.get('CODEX_WORKTREE_REDIRECT'):
    import shutil, subprocess
    shadow = Path(os.environ['CODEX_WORKTREE_REDIRECT'])
    shadow.mkdir()
    shutil.copy2('app.txt', shadow / 'app.txt')
    Path('app.txt').write_text('dirty original' + chr(10))
    subprocess.run(['git', 'config', 'core.worktree', str(shadow)], check=True)
if os.environ.get('CODEX_STAGE_AND_RESTORE'):
    import subprocess
    original = subprocess.run(['git', 'show', 'HEAD:app.txt'], capture_output=True,
                              text=True, check=True).stdout
    Path('app.txt').write_text('staged value' + chr(10))
    subprocess.run(['git', 'add', 'app.txt'], check=True)
    Path('app.txt').write_text(original)
if os.environ.get('CODEX_FORGE_INDEX_STAT'):
    import hashlib, struct, subprocess, time
    time.sleep(1.1)
    raw_index = subprocess.run(['git', 'rev-parse', '--git-path', 'index'],
                               capture_output=True, text=True, check=True).stdout.strip()
    index = Path(raw_index)
    if not index.is_absolute():
        index = Path.cwd() / index
    data = bytearray(index.read_bytes())
    if data[:4] != b'DIRC' or int.from_bytes(data[4:8], 'big') != 2:
        raise ValueError('fixture requires a v2 Git index')
    info = Path('app.txt').stat()
    fields = (info.st_ctime_ns // 10**9, info.st_ctime_ns % 10**9,
              info.st_mtime_ns // 10**9, info.st_mtime_ns % 10**9,
              info.st_dev, info.st_ino, info.st_mode, info.st_uid,
              info.st_gid, info.st_size)
    data[12:52] = struct.pack('>10I', *(value & 0xffffffff for value in fields))
    object_format = subprocess.run(['git', 'rev-parse', '--show-object-format'],
                                   capture_output=True, text=True, check=True).stdout.strip()
    digest = hashlib.sha1 if object_format == 'sha1' else hashlib.sha256
    hash_size = digest().digest_size
    data[-hash_size:] = digest(data[:-hash_size]).digest()
    index.write_bytes(data)
last = Path(sys.argv[sys.argv.index('--output-last-message') + 1])
last.write_text('Fixture handoff')
race = os.environ.get('RACE_OUTPUT')
if race: Path(race).write_text('independent file created during rescue')
relocated = os.environ.get('RACE_DIRECTORY_OUTPUT')
if relocated:
    parent = Path(relocated).parent
    parent.rename(parent.with_name(parent.name + '-moved'))
    parent.mkdir()
    Path(relocated).write_text('stale rescue report')
sys.exit(int(os.environ.get('CODEX_EXIT', '0')))
''')
        self.fake('claude', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CLAUDE_PROMPT')
if capture: Path(capture).write_text(prompt)
action = os.environ.get('CLAUDE_ACTION', '')
if action: Path('app.txt').write_text(action + '\\n')
print('Fixture fallback handoff')
sys.exit(int(os.environ.get('CLAUDE_EXIT', '0')))
''')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(f'#!{sys.executable}\n{body}')
        path.chmod(0o700)

    def invoke(self, *, output=None, packet=None, wal=None,
               env=None, watchdog_seconds=STANDARD_HELPER_WATCHDOG_SECONDS):
        command = [sys.executable, str(RESCUE), '--repo', str(self.repo), '--packet', str(packet or self.packet),
                   '--output', str(output or self.output)]
        if wal is not None:
            command += ['--wal', str(wal)]
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin', **(env or {})}
        return subprocess.run(command, text=True, capture_output=True, env=environment,
                              timeout=watchdog_seconds)

    def test_successful_model_edit_requires_main_commit_without_index_mutation(self):
        index_before = (self.repo / '.git/index').read_bytes()
        result = self.invoke(env={'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertFalse(report['snapshot_commit_by_wrapper'])
        self.assertEqual(report['snapshot_error'], '')
        self.assertEqual(report['exit'], 0)
        self.assertEqual(report['commits'], 0)
        self.assertTrue(report['dirty'])
        self.assertEqual(report['head'], self.base)
        self.assertEqual((self.repo / '.git/index').read_bytes(), index_before)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_model_committed_clean_worktree_still_needs_main_verification(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-verification')
        self.assertEqual(report['commits'], 1)
        self.assertFalse(report['dirty'])
        self.assertFalse(report['snapshot_commit_by_wrapper'])
        self.assertEqual(git(self.repo, 'show', 'HEAD:app.txt'), 'updated')

    def test_clean_descendant_with_ignorecase_config_still_needs_verification(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_SET_IGNORECASE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-verification')
        self.assertFalse(report['dirty'])

    def test_case_variant_addition_cannot_hide_dirty_descendant(self):
        if (self.repo / 'APP.TXT').exists():
            self.skipTest('requires a case-sensitive filesystem')
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_ADD_CASE_VARIANT': '1'})
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        self.assertEqual(git(self.repo, '-c', 'core.ignoreCase=false',
                             'status', '--porcelain'), '?? APP.TXT')
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertTrue(report['dirty'])

    def test_case_variant_after_failed_model_suppresses_fallback(self):
        if (self.repo / 'APP.TXT').exists():
            self.skipTest('requires a case-sensitive filesystem')
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_ADD_CASE_VARIANT': '1', 'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertFalse(capture.exists())

    def two_commit_base(self):
        ancestor = self.base
        git(self.repo, 'commit', '--allow-empty', '-qm', 'approved base')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        return ancestor

    def test_clean_reset_to_ancestor_is_blocked(self):
        ancestor = self.two_commit_base()
        result = self.invoke(env={'CODEX_RESET_TO': ancestor})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['base'], self.base)
        self.assertEqual(report['head'], ancestor)
        self.assertEqual(report['commits'], 0)
        self.assertFalse(report['dirty'])

    def test_divergent_sibling_commit_is_blocked(self):
        ancestor = self.two_commit_base()
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_DIVERGE': '1'})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['commits'], 1)
        self.assertFalse(report['dirty'])
        self.assertNotEqual(report['head'], self.base)

    def test_dirty_reset_to_ancestor_is_blocked(self):
        ancestor = self.two_commit_base()
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_DIRTY_AFTER_RESET': '1'})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertTrue(report['dirty'])
        self.assertEqual(report['head'], ancestor)

    def test_failed_model_reset_does_not_invoke_fallback(self):
        ancestor = self.two_commit_base()
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertEqual(report['head'], ancestor)
        self.assertFalse(capture.exists())

    def test_graft_spoofed_ancestor_reset_is_blocked(self):
        ancestor = self.two_commit_base()
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_GRAFT_BASE': self.base})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['commits'], 0)
        self.assertEqual(report['head'], ancestor)

    def test_initial_graft_refuses_model_launch(self):
        graft = Path(git(self.repo, 'rev-parse', '--git-path', 'info/grafts'))
        if not graft.is_absolute():
            graft = self.repo / graft
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text('# synthetic graft marker\n')
        capture = self.root / 'model-prompt.txt'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())

    def test_failed_model_graft_only_suppresses_fallback(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_GRAFT_ONLY': '1', 'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertFalse(capture.exists())

    def test_graft_added_after_presence_check_cannot_spoof_history(self):
        ancestor = self.two_commit_base()
        git(self.repo, 'reset', '--hard', '-q', ancestor)
        self.assertFalse(rescue.has_grafts(self.repo))
        graft = Path(git(self.repo, 'rev-parse', '--git-path', 'info/grafts'))
        if not graft.is_absolute():
            graft = self.repo / graft
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text(self.base + '\n' + ancestor + ' ' + self.base + '\n')
        self.assertEqual(git(self.repo, 'rev-list', '--count',
                             f'{self.base}..{ancestor}'), '1')
        self.assertEqual(rescue.git(self.repo, 'rev-list', '--count',
                                    f'{self.base}..{ancestor}'), '0')
        self.assertFalse(rescue.base_is_ancestor(self.repo, self.base, ancestor))

    def test_forged_commit_graph_parent_does_not_accept_sibling(self):
        ancestor = self.two_commit_base()
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_DIVERGE': '1',
                                  'CODEX_FORGE_GRAPH_PARENT': self.base})
        head = git(self.repo, 'rev-parse', 'HEAD')
        self.assertEqual(subprocess.run(
            ['git', '-C', str(self.repo), 'merge-base', '--is-ancestor', self.base, head]
        ).returncode, 0)
        self.assertEqual(subprocess.run(
            ['git', '-C', str(self.repo), '-c', 'core.commitGraph=false',
             'merge-base', '--is-ancestor', self.base, head]
        ).returncode, 1)
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['commits'], 1)

    def test_forged_commit_graph_tree_does_not_hide_staged_edit(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_STAGE_AFTER_COMMIT': '1',
                                  'CODEX_FORGE_GRAPH_TREE': '1'})
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        self.assertEqual(git(self.repo, '-c', 'core.commitGraph=false',
                             'status', '--porcelain'), 'M  app.txt')
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertTrue(report['dirty'])
        self.assertEqual(report['commits'], 1)

    def test_linked_worktree_forged_commit_graph_is_ignored(self):
        ancestor = self.two_commit_base()
        linked = self.root / 'linked'
        git(self.repo, 'worktree', 'add', '-q', '-b', 'linked', str(linked), self.base)
        self.repo = linked
        result = self.invoke(env={'CODEX_RESET_TO': ancestor, 'CODEX_DIVERGE': '1',
                                  'CODEX_FORGE_GRAPH_PARENT': self.base})
        graph = Path(git(linked, 'rev-parse', '--git-path', 'objects/info/commit-graph'))
        if not graph.is_absolute():
            graph = linked / graph
        self.assertTrue(graph.is_file())
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')

    def test_linked_worktree_gitdir_redirect_is_blocked(self):
        primary = self.repo
        linked = self.root / 'linked'
        git(primary, 'worktree', 'add', '-q', '-b', 'linked', str(linked))
        self.repo = linked
        approved_gitdir = git(linked, 'rev-parse', '--absolute-git-dir')
        result = self.invoke(env={'CODEX_REDIRECT_GITDIR': '1',
                                  'CODEX_PRIMARY_REPO': str(primary),
                                  'CODEX_SHADOW_REPO': str(self.root / 'shadow')})
        self.assertNotEqual(git(linked, 'rev-parse', '--absolute-git-dir'), approved_gitdir)
        self.assertEqual(git(primary, 'rev-parse', 'refs/heads/linked'), self.base)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')

    def test_linked_worktree_common_dir_redirect_is_blocked(self):
        primary = self.repo
        linked = self.root / 'linked'
        git(primary, 'worktree', 'add', '-q', '-b', 'linked', str(linked))
        self.repo = linked
        approved_gitdir = git(linked, 'rev-parse', '--absolute-git-dir')
        approved_common = git(linked, 'rev-parse', '--git-common-dir')
        result = self.invoke(env={'CODEX_REDIRECT_COMMON_DIR': '1',
                                  'CODEX_PRIMARY_REPO': str(primary),
                                  'CODEX_SHADOW_REPO': str(self.root / 'shadow')})
        self.assertEqual(git(linked, 'rev-parse', '--absolute-git-dir'), approved_gitdir)
        self.assertNotEqual(git(linked, 'rev-parse', '--git-common-dir'), approved_common)
        self.assertEqual(git(primary, 'rev-parse', 'refs/heads/linked'), self.base)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')

    def test_gitdir_redirect_at_same_head_suppresses_fallback(self):
        primary = self.repo
        linked = self.root / 'linked'
        git(primary, 'worktree', 'add', '-q', '-b', 'linked', str(linked))
        self.repo = linked
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_REDIRECT_GITDIR': '1',
                                  'CODEX_SHADOW_NO_COMMIT': '1',
                                  'CODEX_PRIMARY_REPO': str(primary),
                                  'CODEX_SHADOW_REPO': str(self.root / 'shadow'),
                                  'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertFalse(capture.exists())

    def test_worktree_config_redirect_does_not_hide_dirty_original(self):
        shadow = self.root / 'shadow-worktree'
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_WORKTREE_REDIRECT': str(shadow)})
        self.assertEqual(git(self.repo, 'rev-parse', '--show-toplevel'),
                         str(shadow.resolve()))
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        self.assertEqual((self.repo / 'app.txt').read_text(), 'dirty original\n')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')

    def test_worktree_config_redirect_at_same_head_suppresses_fallback(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_WORKTREE_REDIRECT': str(self.root / 'shadow-worktree'),
                                  'CODEX_EXIT': '7', 'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertFalse(capture.exists())

    def test_forged_index_stat_does_not_hide_dirty_descendant(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_DIRTY_AFTER_COMMIT': '1',
                                  'CODEX_FORGE_INDEX_STAT': '1'})
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        self.assertEqual((self.repo / 'app.txt').read_text(), 'new dirty edit\n')
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertTrue(report['dirty'])
        self.assertEqual(report['commits'], 1)

    def test_forged_index_stat_after_failed_model_suppresses_fallback(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_ACTION': 'changed', 'CODEX_FORGE_INDEX_STAT': '1',
                                  'CODEX_EXIT': '7', 'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['source'], 'Codex gpt-6-astra')
        self.assertFalse(capture.exists())

    def test_staged_only_edit_with_clean_worktree_needs_main_commit(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_STAGE_AND_RESTORE': '1'})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertEqual(report['commits'], 1)
        self.assertEqual(git(self.repo, 'show', ':app.txt'), 'staged value')
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')

    def test_clean_inspection_does_not_refresh_source_index(self):
        tracked = self.repo / 'app.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        index = self.repo / '.git/index'
        before = index.read_bytes()
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')
        self.assertEqual(index.read_bytes(), before)

    def test_private_inspection_does_not_create_shared_index(self):
        git(self.repo, 'config', 'core.splitIndex', 'true')
        git(self.repo, 'update-index', '--split-index')
        gitdir = self.repo / '.git'
        index_before = (gitdir / 'index').read_bytes()
        shared_before = {path.name: path.read_bytes()
                         for path in gitdir.glob('sharedindex.*')}
        self.assertTrue(shared_before)
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'blocked')
        self.assertEqual((gitdir / 'index').read_bytes(), index_before)
        self.assertEqual({path.name: path.read_bytes()
                          for path in gitdir.glob('sharedindex.*')}, shared_before)

    def test_dirty_descendant_commit_still_needs_main_commit(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated', 'CODEX_COMMIT': '1',
                                  'CODEX_DIRTY_AFTER_COMMIT': '1'})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertEqual(report['commits'], 1)
        self.assertTrue(report['dirty'])
        self.assertEqual(report['exit'], 0)

    def test_ancestry_inspection_error_is_not_divergence(self):
        with patch.object(rescue, 'run_process', return_value=subprocess.CompletedProcess(
                ['git'], 128, '', 'fixture error')):
            with self.assertRaises(subprocess.CalledProcessError):
                rescue.base_is_ancestor(self.repo, self.base, self.base)

    def test_linked_worktree_uses_common_git_graft_path(self):
        linked = self.root / 'linked'
        git(self.repo, 'worktree', 'add', '-q', '-b', 'linked', str(linked))
        graft = Path(git(linked, 'rev-parse', '--git-path', 'info/grafts'))
        if not graft.is_absolute():
            graft = linked / graft
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text('fixture\n')
        self.assertTrue(rescue.has_grafts(linked))

    def test_rescue_refuses_clean_commit_on_a_different_branch(self):
        result = self.invoke(env={'CODEX_SWITCH_BRANCH': '1', 'CAPTURE_CLAUDE_PROMPT': str(self.root / 'fallback')})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['branch'], 'feat/rescue')
        self.assertEqual(report['actual_branch'], 'feat/wrong')
        self.assertFalse((self.root / 'fallback').exists())

    def test_rescue_refuses_local_filter_before_status_executes_it(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        git(self.repo, 'add', '.gitattributes')
        git(self.repo, 'commit', '-qm', 'mark filter')
        marker = self.root / 'filter-ran'
        git(self.repo, 'config', 'filter.fixture.clean',
            f"sh -c 'touch {shlex.quote(str(marker))}; cat'")
        tracked = self.repo / 'app.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.output.exists())

    def test_rescue_refuses_untracked_file_hidden_by_status_config(self):
        git(self.repo, 'config', 'status.showUntrackedFiles', 'no')
        (self.repo / 'unreviewed.txt').write_text('unreviewed\n')
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        capture = self.root / 'model-prompt'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())

    def test_rescue_blocks_if_model_adds_local_filter_before_postcheck(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        git(self.repo, 'add', '.gitattributes')
        git(self.repo, 'commit', '-qm', 'mark filter')
        marker = self.root / 'post-model-filter-ran'
        fallback = self.root / 'fallback'
        result = self.invoke(env={'CODEX_LOCAL_FILTER': str(marker),
                                  'CAPTURE_CLAUDE_PROMPT': str(fallback)})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('inspect it before retrying', result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.output.exists())
        self.assertFalse(fallback.exists())

    def test_failed_model_after_edits_does_not_fallback_or_commit(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_ACTION': 'unfinished', 'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stdout)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['head'], self.base)
        self.assertTrue(report['dirty'])
        self.assertFalse(capture.exists())

    def test_fallback_before_edits_is_blind_and_handed_off(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_EXIT': '7', 'CLAUDE_ACTION': 'fallback',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)},
                             watchdog_seconds=FUNCTIONAL_HELPER_WATCHDOG_SECONDS)
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['source'], 'Claude Fable fallback')
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertEqual(report['head'], self.base)
        self.assertTrue(report['dirty'])
        self.assertIn('A disposable rescue packet', capture.read_text())
        self.assertNotIn('Fixture handoff', capture.read_text())

    def test_output_symlink_does_not_delete_target(self):
        target = self.root / 'important.txt'
        target.write_text('preserve')
        self.output.symlink_to(target)
        result = self.invoke(env={'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), self.base)

    def test_existing_unrelated_file_outside_repo_is_not_deleted(self):
        important = self.root / 'ssh-config'
        important.write_text('important configuration\n')
        capture = self.root / 'model.capture'
        result = self.invoke(output=important, env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(important.read_text(), 'important configuration\n')
        self.assertFalse(capture.exists())

    def test_file_created_during_rescue_is_not_overwritten(self):
        result = self.invoke(env={'RACE_OUTPUT': str(self.output), 'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(self.output.read_text(), 'independent file created during rescue')
        self.assertIn('inspect the worktree', result.stderr)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')

    def test_relocated_report_directory_preserves_replacement_after_rescue_edits(self):
        reports = self.root / 'reports'
        reports.mkdir()
        output = reports / 'report.json'
        result = self.invoke(output=output, env={'RACE_DIRECTORY_OUTPUT': str(output),
                                                 'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(output.read_text(), 'stale rescue report')
        self.assertFalse((self.root / 'reports-moved/report.json').exists())
        self.assertIn('inspect the worktree', result.stderr)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')

    def test_packet_symlink_is_not_sent_to_model(self):
        private = self.root / 'private.txt'
        private.write_text('private fixture')
        link = self.root / 'packet-link.md'
        link.symlink_to(private)
        capture = self.root / 'codex-prompt.txt'
        result = self.invoke(packet=link, env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())

    def test_packet_hardlink_fifo_and_oversize_are_refused_before_model_call(self):
        private = self.root / 'private.txt'
        private.write_text('private fixture')
        hardlink = self.root / 'linked.md'
        os.link(private, hardlink)
        fifo = self.root / 'pipe.md'
        os.mkfifo(fifo)
        large = self.root / 'large.md'
        large.write_bytes(b'x' * 150001)
        for packet in (hardlink, fifo, large):
            with self.subTest(packet=packet.name):
                capture = self.root / f'{packet.name}.capture'
                result = self.invoke(packet=packet, env={'CAPTURE_CODEX_PROMPT': str(capture)})
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(capture.exists())

    def test_existing_output_directory_is_reported_without_model_call(self):
        self.output.mkdir()
        capture = self.root / 'model.capture'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())
        self.assertTrue(self.output.is_dir())

    def test_invalid_subdirectory_repo_cannot_delete_tracked_output(self):
        subdir = self.repo / 'subdir'
        subdir.mkdir()
        tracked = self.repo / 'app.txt'
        result = subprocess.run([sys.executable, str(RESCUE), '--repo', str(subdir),
                                 '--packet', str(self.packet), '--output', str(tracked)],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(tracked.read_text(), 'baseline\n')

    def test_packet_parent_alias_cannot_be_deleted_as_output(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        result = self.invoke(packet=alias / 'packet.md', output=self.packet)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(self.packet.read_text(), 'A disposable rescue packet.')

    def test_case_aliases_cannot_delete_repo_file_or_packet(self):
        alias_repo = self.repo.parent / self.repo.name.upper()
        alias_packet = self.packet.with_name(self.packet.name.upper())
        if not alias_repo.exists() or not alias_repo.samefile(self.repo) or not alias_packet.exists():
            self.skipTest('filesystem is case-sensitive')
        first = self.invoke(output=alias_repo / 'app.txt')
        self.assertEqual(first.returncode, 2, first.stdout)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'baseline\n')
        second = self.invoke(output=alias_packet)
        self.assertEqual(second.returncode, 2, second.stdout)
        self.assertEqual(self.packet.read_text(), 'A disposable rescue packet.')

    def test_hardlinked_packet_cannot_be_unlinked_as_output(self):
        alias = self.root / 'packet-hardlink.md'
        os.link(self.packet, alias)
        result = self.invoke(output=alias)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertTrue(alias.exists())
        self.assertTrue(self.packet.exists())

    def test_wal_symlink_and_hardlink_do_not_modify_outside_file(self):
        with patch.dict(os.environ, {'HOME': str(self.root)}):
            directory = self.root / '.claude/wals/session-1'
            directory.mkdir(parents=True)
            for kind in ('symlink', 'hardlink'):
                with self.subTest(kind=kind):
                    target = self.root / f'outside-{kind}.txt'
                    target.write_text('preserve\n')
                    wal = directory / 'main.jsonl'
                    wal.unlink(missing_ok=True)
                    if kind == 'symlink':
                        wal.symlink_to(target)
                    else:
                        os.link(target, wal)
                    with self.assertRaises((ValueError, OSError)):
                        rescue.log(wal, {'event': 'probe'})
                    self.assertEqual(target.read_text(), 'preserve\n')

    def test_wal_outside_private_root_is_rejected(self):
        outside = self.root / 'arbitrary.txt'
        with patch.dict(os.environ, {'HOME': str(self.root)}):
            with self.assertRaises((ValueError, OSError)):
                rescue.log(outside, {'event': 'probe'})
        self.assertFalse(outside.exists())

    def test_model_hardlink_is_left_for_main_without_committing_outside_bytes(self):
        outside = self.root / 'outside-private.txt'
        outside.write_text('private fixture bytes\n')
        index_before = (self.repo / '.git/index').read_bytes()
        result = self.invoke(env={'CODEX_LINK_OUTSIDE': str(outside)})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-commit')
        self.assertEqual(report['head'], self.base)
        self.assertTrue(report['dirty'])
        self.assertEqual((self.repo / '.git/index').read_bytes(), index_before)
        self.assertEqual(git(self.repo, 'show', 'HEAD:app.txt'), 'baseline')
        self.assertEqual(outside.read_text(), 'private fixture bytes\n')


if __name__ == '__main__':
    unittest.main()
