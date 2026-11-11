"""Install Harness Mission Control, the local realtime fleet dashboard (GoodQA #15585, docs/mission-control.md).

The server and its web assets are copied from harness/mission_control/ to ~/.agent-harness/mission-control/app/
(staged, then swapped in by rename; the previous copy is kept as app.prev for rollback). On macOS the LaunchAgent
com.agent-harness.mission-control is (re)registered through the installed `server.py install-launchd --apply`, so
it always points at the installed copy, never at a checkout or worktree.

Like netwatch, this step never fails the harness install: it reports one status line. `--no-mission-control`
opts out and is remembered; where installed it stops the LaunchAgent (files and chat data stay). The LaunchAgent
belongs to the real user, so with a non-default --home (tests, staging a home) the service is never touched and
the files are only copied when --mission-control asks for them.
"""

from __future__ import annotations

import json
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import http.client
import re
import time
import os
import shlex
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "harness" / "mission_control"
STATE_FILE = "mission-control-state.json"
LABEL = "com.agent-harness.mission-control"
SKIP_DIRS = {"__pycache__", "tests"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
MAX_FILE = 8 << 20  # the vendored three.js module is the largest file, well under this


def mc_root(home: Path) -> Path:
    return home / ".agent-harness" / "mission-control"


def app_dir(home: Path) -> Path:
    return mc_root(home) / "app"


def real_home() -> Path:
    """The account's home from the password database: a LaunchAgent belongs to the real user, not to $HOME."""
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError):
        return Path.home().resolve()


def read_state(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return json.loads(os.read(fd, 4096).decode())
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def real_dir(path: Path) -> None:
    """Create path (0700) if missing; refuse a symlink or a non-directory."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"{path} must be a real directory, not a link")


def choice(home: Path, flag) -> bool:
    """--mission-control/--no-mission-control win; otherwise the saved choice; otherwise on."""
    if flag is not None:
        return bool(flag)
    state = read_state(home / ".agent-harness" / STATE_FILE)
    return not (isinstance(state, dict) and state.get("enabled") is False)


def save_choice(home: Path, enabled: bool) -> None:
    directory = home / ".agent-harness"
    real_dir(directory)
    temporary = directory / f".{STATE_FILE}.{secrets.token_hex(4)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"schema": 1, "enabled": enabled}, handle)
        handle.write("\n")
    os.replace(temporary, directory / STATE_FILE)


def source_files(source: Path = SOURCE) -> list[Path]:
    """Every regular file the app needs, relative to source; a symlink in the checkout is refused, not followed."""
    files = []
    if source.is_symlink() or not source.is_dir():
        raise OSError('unsafe component source root')
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False, onerror=_walk_error):
        if any((Path(dirpath)/name).is_symlink() for name in dirnames
               if name not in SKIP_DIRS and not name.startswith('.')):
            raise OSError('component source directory alias retained')
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name.startswith(".") or path.suffix in SKIP_SUFFIXES:
                continue
            if path.is_symlink() or not path.is_file():
                raise OSError(f"refusing a non-regular source file: {path.relative_to(source)}")
            if path.stat().st_size > MAX_FILE:
                raise OSError(f"source file too large: {path.relative_to(source)}")
            files.append(path.relative_to(source))
    if Path("server.py") not in files or Path("web/index.html") not in files:
        raise OSError("harness/mission_control is incomplete (server.py or web/index.html missing)")
    return files


INSTALL_JOURNAL = "app-install-transaction.json"
MAX_TREE_BYTES = 128 << 20


def _walk_error(error):
    raise OSError('component traversal incomplete') from None


@contextlib.contextmanager
def install_lock(home):
    for path in (home / ".agent-harness", mc_root(home)):
        real_dir(path)
    path = mc_root(home) / ".install.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
            raise OSError("unsafe installation lock")
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OSError("installation busy")
                time.sleep(.02)
        if os.stat(path, follow_symlinks=False).st_ino != info.st_ino:
            raise OSError("installation lock changed")
        yield
    finally:
        os.close(fd)


def _sync(root):
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _save(root, value):
    path = root / (".journal-" + secrets.token_hex(8))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path, root / INSTALL_JOURNAL)
    _sync(root)


def _tree(path):
    if path.is_symlink():
        raise OSError('component alias retained')
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_dir():
        raise OSError("unsafe component directory")
    allowed = {str(p) for p in source_files(SOURCE)}
    digest, total, count = hashlib.sha256(), 0, 0
    for directory, dirs, names in os.walk(path, followlinks=False, onerror=_walk_error):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise OSError("unknown component alias")
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(names):
            item = Path(directory) / name
            rel = item.relative_to(path).as_posix()
            if rel not in allowed:
                raise OSError("unknown component payload retained; inspect before replacing")
            info = os.stat(item,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
                raise OSError("unsafe component file")
            total += info.st_size
            count += 1
            if total > MAX_TREE_BYTES or count > 256:
                raise OSError("component bound exceeded")
            fd = os.open(item, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                before = os.fstat(fd)
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    data = stream.read(MAX_FILE + 1)
                after = os.fstat(fd)
                named = os.stat(item,follow_symlinks=False)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino) or len(data)!=before.st_size:
                    raise OSError('component changed')
            finally:
                os.close(fd)
            digest.update(rel.encode() + b'\0' + hashlib.sha256(data).digest())
    info = path.stat()
    return {"dev": info.st_dev, "ino": info.st_ino, "digest": digest.hexdigest()}


def _exchange(root, left, right):
    # No two-rename fallback: canonical app must exist throughout an upgrade.
    fd = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == 'darwin':
            function = library.renameatx_np
        elif sys.platform.startswith('linux'):
            function = library.renameat2
        else:
            raise OSError('atomic directory exchange unsupported')
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        if function(fd, os.fsencode(left), fd, os.fsencode(right), 2):
            raise OSError(ctypes.get_errno(), 'atomic directory exchange refused')
        _sync(root)
    except AttributeError:
        raise OSError('atomic directory exchange unavailable') from None
    finally:
        os.close(fd)


def _matches(path, expected):
    return _tree(path) == expected


def _journal(root):
    path = root / INSTALL_JOURNAL
    if path.is_symlink():
        raise OSError('journal alias retained')
    if not path.exists():
        return None
    info = os.stat(path,follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size > 8192:
        raise OSError('unsafe installation journal')
    def unique(pairs):
        result={}
        for key,item in pairs:
            if key in result:
                raise ValueError('duplicate journal field')
            result[key]=item
        return result
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    try:
        before=os.fstat(fd)
        raw=os.read(fd,8193)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)>8192:
            raise OSError('journal changed')
        value=json.loads(raw,object_pairs_hook=unique)
    finally:
        os.close(fd)
    keys = {'schema','op','phase','old','new','previous','mode','activation'}
    if (not isinstance(value, dict) or set(value) != keys or value['schema'] != 'mc.app-install/1'
            or not isinstance(value['op'],str) or not re.fullmatch('[0-9a-f]{24}',value['op'])
            or value['phase'] not in ('PREPARED','PUBLISHED','VERIFIED','COMMITTED','ROLLED_BACK','ROLLED_BACK_LEGACY')
            or value['mode'] not in ('copy','service') or not isinstance(value['activation'],str)
            or not re.fullmatch('[0-9a-f]{32}',value['activation'])):
        raise OSError('unknown installation journal; retained')
    for key in ('old','new','previous'):
        item=value[key]
        if item is None and key != 'new':
            continue
        if (not isinstance(item,dict) or set(item)!={'dev','ino','digest'} or type(item['dev']) is not int
                or type(item['ino']) is not int or not isinstance(item['digest'],str)
                or not re.fullmatch('[0-9a-f]{64}',item['digest'])):
            raise OSError('invalid installation binding')
    return value


def _recover(home, activate=None, verify=None, fault=lambda phase: None):
    root, app = mc_root(home), app_dir(home)
    journal = _journal(root)
    if journal is None:
        return
    stage, retained = root / ('.app-' + journal['op']), root / ('.prev-' + journal['op'])
    previous = root / 'app.prev'
    phase = journal['phase']
    if phase in ('COMMITTED','ROLLED_BACK','ROLLED_BACK_LEGACY'):
        expected = journal['new'] if phase == 'COMMITTED' else journal['old']
        if not _matches(app,expected):
            raise OSError('settled installation changed; retained')
        return
    if phase in ('PREPARED','PUBLISHED'):
        if _matches(app,journal['new']):
            if journal['old'] is None:
                if journal['mode']!='service' or activate is None or verify is None:
                    raise OSError('first installation unverified; retained for reconciliation')
                nonce=secrets.token_hex(16)
                if not activate(nonce) or not verify(journal['new']['digest'],nonce):
                    raise OSError('first installation activation still unverified; retained')
                journal['phase']='VERIFIED';journal['activation']=nonce
                _save(root,journal)
                return _recover(home,activate,verify,fault)
            if not _matches(stage,journal['old']):
                raise OSError('old component binding missing; retained')
            _exchange(root, 'app', stage.name)
        elif not _matches(app,journal['old']) or not _matches(stage,journal['new']):
            raise OSError('interrupted installation binding unknown; retained')
        if not _matches(previous,journal['previous']):
            raise OSError('rollback copy changed; retained')
        if journal['old'] is None:
            # Exact pre-publication first install: there is no prior runtime to activate.
            # Keep the proved staged tree, settle the safe abort, then permit a fresh normal attempt.
            journal['phase']='ROLLED_BACK'
            _save(root,journal)
            return
        if journal['mode']=='service':
            if activate is None or verify is None:
                raise OSError('service rollback requires activation reconciliation')
            nonce=secrets.token_hex(16)
            legacy='--activation-id' not in (app/'server.py').read_text()
            if legacy:
                if not activate(None):
                    raise OSError('old canonical restored; legacy rollback activation failed')
                journal['phase']='ROLLED_BACK_LEGACY'
                _save(root,journal)
                raise OSError('old canonical restored and legacy activation requested; runtime unverified')
            if not activate(nonce) or not verify(journal['old']['digest'],nonce):
                raise OSError('old canonical restored; rollback service unverified')
        journal['phase']='ROLLED_BACK'
        _save(root,journal)
        return
    # VERIFIED was durable before any backup move. Reconcile exact objects at either name.
    if not _matches(app,journal['new']):
        raise OSError('verified component changed')
    if journal['old'] is not None:
        if _matches(stage,journal['old']):
            if journal['previous'] is not None and _matches(previous,journal['previous']):
                if retained.exists():
                    raise OSError('retained backup collision')
                os.rename(previous,retained)
                _sync(root)
                fault('after_previous_retained')
            elif journal['previous'] is not None and not _matches(retained,journal['previous']):
                raise OSError('previous backup binding missing')
            elif journal['previous'] is None and previous.exists():
                raise OSError('unexpected previous backup')
            os.rename(stage,previous)
            _sync(root)
            fault('after_previous_promoted')
        elif not _matches(previous,journal['old']):
            raise OSError('old verified predecessor missing')
    journal['phase']='COMMITTED'
    _save(root,journal)


def _install_locked(home, source, activate=None, verify=None, fault=lambda phase: None):
    root, app = mc_root(home), app_dir(home)
    _recover(home,activate,verify,fault)
    # Retain evidence rather than pruning unknown/failed versions. Bounded storage requires operator review.
    artifacts=[p for p in root.iterdir() if p.name.startswith(('.app-','.prev-'))]
    if len(artifacts)>=8:
        raise OSError('retained component limit; inspect recovery before retry')
    files=source_files(source)
    old, previous = _tree(app), _tree(root/'app.prev')
    op=secrets.token_hex(12)
    stage=root/('.app-'+op)
    stage.mkdir(mode=0o700)
    for relative in files:
        target=stage/relative
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        data=(source/relative).read_bytes()
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    for directory,_,_ in os.walk(stage,topdown=False,onerror=_walk_error):
        _sync(Path(directory))
    new=_tree(stage)
    journal={'schema':'mc.app-install/1','op':op,'phase':'PREPARED','old':old,'new':new,
             'previous':previous,'mode':'service' if activate else 'copy','activation':secrets.token_hex(16)}
    _save(root,journal);fault('prepared')
    if old is None:
        os.rename(stage,app);_sync(root)
    else:
        _exchange(root,stage.name,'app')
    fault('after_exchange')
    journal['phase']='PUBLISHED';_save(root,journal);fault('published')
    if activate is not None and (not activate(journal['activation']) or verify is None or not verify(new['digest'],journal['activation'])):
        if old is not None:
            _recover(home,activate,verify,fault)
        raise OSError('candidate activation failed; retained for reconciliation')
    journal['phase']='VERIFIED';_save(root,journal);fault('verified')
    _recover(home,activate,verify,fault)
    return len(files)


def install_app(home: Path, source: Path = SOURCE, *, fault=lambda phase: None) -> int:
    """Private copy-only component publication; real service upgrades use coordinated status()."""
    if home.resolve()==real_home():
        raise OSError('real-home component requires coordinated activation')
    with install_lock(home):
        return _install_locked(home,source,fault=fault)


LAUNCHER_MARK = "# agent-harness mission-control launcher"


def launcher_text(home: Path) -> str:
    server = app_dir(home) / "server.py"
    return (f"#!/bin/sh\n{LAUNCHER_MARK}: opens the dashboard with a fresh one-time link.\n"
            f"exec /usr/bin/python3 {shlex.quote(str(server))} open \"$@\"\n")


def install_launcher(home: Path) -> str:
    """~/.local/bin/mc runs `server.py open`. Never replaces a file the installer did not write."""
    bindir = home / ".local" / "bin"
    target = bindir / "mc"
    try:
        bindir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if bindir.is_symlink() or not bindir.is_dir():
            return f"launcher skipped: {bindir} is not a real directory"
        if target.is_symlink() or (target.exists() and LAUNCHER_MARK not in target.read_text(errors="replace")[:400]):
            return f"launcher skipped: {target} exists and is not ours"
        temporary = bindir / f".mc.{secrets.token_hex(4)}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o755)
        with os.fdopen(fd, "w") as handle:
            handle.write(launcher_text(home))
        os.replace(temporary, target)
        return f"launcher {target}"
    except OSError as error:
        return f"launcher skipped ({error.__class__.__name__})"


def default_runner(argv: list[str]):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False)


def service_argv(home: Path, verb: str, python: str = "/usr/bin/python3", activation=None) -> list[str]:
    """The installed server's own launchd command; /usr/bin/python3 survives Homebrew upgrades."""
    argv = [python, str(app_dir(home) / "server.py"), verb, "--apply"]
    if verb == "install-launchd":
        argv += ["--python", python]
        if activation:
            argv += ["--activation-id", activation]
    return argv


def run_service(home: Path, verb: str, run, activation=None) -> str:
    try:
        result = run(service_argv(home, verb, activation=activation))
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"{verb} failed ({error.__class__.__name__})"
    code = getattr(result, "returncode", 1)
    if code:
        return f'{verb} failed (exit {code})'
    return "ok"


def _service_state(run):
    try:
        result=run(['launchctl','print',f'gui/{os.getuid()}/{LABEL}'])
    except (OSError,subprocess.TimeoutExpired):
        return 'unknown',None
    if result.returncode==0:
        match=re.search(r'^\s*pid = ([1-9][0-9]*)\s*$',getattr(result,'stdout','') or '',re.M)
        return 'loaded',int(match[1]) if match else None
    if result.returncode==113 and 'Could not find service' in (getattr(result,'stderr','') or ''):
        return 'absent',None
    return 'unknown',None


def _verify_service(digest, activation, run, port=47615):
    for attempt in range(5):
        state,pid=_service_state(run)
        if state=='loaded' and pid:
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            try:
                connection.request('GET','/healthz',headers={'Host':f'127.0.0.1:{port}'})
                response=connection.getresponse();raw=response.read(4097)
                def unique(pairs):
                    value={}
                    for key,item in pairs:
                        if key in value:raise ValueError('duplicate health field')
                        value[key]=item
                    return value
                value=json.loads(raw,object_pairs_hook=unique) if len(raw)<=4096 and response.status==200 else None
                if (isinstance(value,dict) and value.get('ok') is True and type(value.get('pid')) is int and value['pid']==pid
                        and value.get('component_digest')==digest and value.get('activation_id')==activation):
                    return True
            except (OSError,ValueError):
                pass
            finally:
                connection.close()
        time.sleep(.2)
    return False


def status(home: Path, apply: bool, flag=None, *, run=None, system: str | None = None,
           source: Path = SOURCE) -> str:
    """One truthful status line; unknown stop/activation never means success."""
    try:
        home=home.expanduser().resolve();system=system or sys.platform
        is_real=home==real_home();enabled=choice(home,flag);runner=run or default_runner
        if not apply:
            if not enabled:
                return 'mission control: would stay off (--no-mission-control remembered)'
            if not is_real and flag is None:
                return 'mission control: skipped (non-default --home; pass --mission-control to copy the files)'
            return f'mission control: would copy {len(source_files(source))} files to {app_dir(home)}'
        if not is_real and flag is None:
            return 'mission control: skipped (non-default --home; pass --mission-control to copy the files)'
        with install_lock(home):
            if flag is not None:
                save_choice(home,enabled)
            if not enabled:
                if is_real and system=='darwin':
                    if (app_dir(home)/'server.py').is_file():
                        result=run_service(home,'uninstall-launchd',runner)
                        state,_=_service_state(runner)
                        if result!='ok' or state!='absent':
                            return 'mission control: off preference remembered; stop failed or job state unknown'
                    else:
                        state,_=_service_state(runner)
                        if state!='absent':
                            return 'mission control: off preference remembered; installed stop helper missing; job loaded or unknown'
                    return 'mission control: off; LaunchAgent stopped (verified absent); files and chat data kept'
                return 'mission control: off (remembered)'
            service=is_real and system=='darwin'
            activate=(lambda nonce: run_service(home,'install-launchd',runner,nonce)=='ok') if service else None
            verify=(lambda digest,nonce: _verify_service(digest,nonce,runner)) if service else None
            count=_install_locked(home,source,activate,verify)
            line=f'mission control: {count} files in {app_dir(home)}'
            if service:
                line+=f'; LaunchAgent {LABEL}: ok (component/PID/activation verified); {install_launcher(home)}'
            elif is_real:
                line+=f'; no launchd on {system}: run installed server.py serve yourself'
            return line
    except Exception as error:
        return f'mission control: failed ({error.__class__.__name__}: {str(error)[:120]}); retained versions require reconciliation'
