#!/usr/bin/env python3
"""1377 v3 F1 tests (receipt bugtracker-pr1377-gate-v2 F1): the containerd config under tomllib and the strict reader."""
import sys

SHT = 'infra/release-harness/test_rw_ship_selfhost.py'


def edit(path, old, new, count=1):
    t = open(path).read()
    n = t.count(old)
    if n != count:
        sys.exit('anchor %r in %s found %d times, want %d' % (old[:60], path, n, count))
    open(path, 'w').write(t.replace(old, new))


edit(SHT, '''@pytest.mark.parametrize('body,why', [
    ("imports = ['/etc/containerd/conf.d/*.toml']\\nroot = '%(r)s'\\n", 'uses imports'),
    ("imports = [\\n  '/x.toml',\\n]\\nroot = '%(r)s'\\n", 'uses imports'),
    ("root = '%(r)s'\\nroot = '/other'\\n", 'sets root 2 times'),
    ("root = 'relative/root'\\n", 'has an unreadable root'),
    ("root = '%(r)s/missing'\\n", 'does not exist'),
])
def test_f1_containerd_config_refusals(F1, body, why):
    cfg = F1.st / 'ctd.toml'; cfg.write_text(body % {'r': F1.st / 'containerd-root'})
    F1.ctd('ctd.sock', ['--config', str(cfg)]); F1.put('ctd-address', F1.sock('ctd.sock'))
    _refused(F1, why)
''', '''# receipt bugtracker-pr1377-gate-v2 F1: every config case runs under tomllib AND under the strict reader used when tomllib
# does not import (python < 3.11; the VM's python is not known here), forced by setting the module's tomllib to None.
PARSERS = ['tomllib', 'fallback']
NOSAFE = 'cannot be read safely without tomllib'


def _parser(F1, monkeypatch, parser):
    if parser == 'fallback': monkeypatch.setattr(F1.M, 'tomllib', None, raising=False)
    else: assert getattr(F1.M, 'tomllib', None) is not None, 'selfhost-ctl.py must use tomllib when it imports'


def _cfg(F1, body, sock='ctd.sock', name='ctd.toml'):
    cfg = F1.st / name; cfg.write_text(body % {'r': F1.st / 'containerd-root'})
    F1.ctd(sock, ['--config', str(cfg)]); F1.put('ctd-address', F1.sock(sock))


@pytest.mark.parametrize('parser', PARSERS)
@pytest.mark.parametrize('body,why', [
    ("imports = ['/etc/containerd/conf.d/*.toml']\\nroot = '%(r)s'\\n", {'tomllib': 'uses imports', 'fallback': 'uses imports'}),
    ("imports = [\\n  '/x.toml',\\n]\\nroot = '%(r)s'\\n", {'tomllib': 'uses imports', 'fallback': NOSAFE}),
    ("root = '%(r)s'\\nroot = '/other'\\n", {'tomllib': 'is not valid TOML', 'fallback': 'sets root 2 times'}),
    ("root = 'relative/root'\\n", {'tomllib': 'has an unreadable root', 'fallback': 'has an unreadable root'}),
    ("root = '%(r)s/missing'\\n", {'tomllib': 'does not exist', 'fallback': 'does not exist'}),
    # quoted imports keys
    ('"imports" = ["/x.toml"]\\nroot = \\'%(r)s\\'\\n', {'tomllib': 'uses imports', 'fallback': NOSAFE}),
    ("'imports' = ['/x.toml']\\nroot = '%(r)s'\\n", {'tomllib': 'uses imports', 'fallback': NOSAFE}),
    # case variants containerd's Go decoder may match: refused on both paths
    ("Root = '%(r)s'\\n", {'tomllib': 'spells root as', 'fallback': 'spells root as'}),
    ("IMPORTS = ['/x.toml']\\n", {'tomllib': 'spells imports as', 'fallback': 'spells imports as'}),
    ('"ROOT" = "%(r)s"\\n', {'tomllib': 'spells root as', 'fallback': NOSAFE}),
    # forms the strict reader never guesses at; tomllib reads them exactly (None: the measured root is the real root)
    ("root.x = 1\\nroot = '%(r)s'\\n", {'tomllib': 'is not valid TOML', 'fallback': NOSAFE}),
    ("x = {root = '/elsewhere'}\\nroot = '%(r)s'\\n", {'tomllib': None, 'fallback': NOSAFE}),
    ("y = 'a'\\nx.root = '/elsewhere'\\nroot = '%(r)s'\\n", {'tomllib': None, 'fallback': NOSAFE}),
    ('root = """%(r)s"""\\n', {'tomllib': None, 'fallback': 'multi-line string'}),
    ("root = \\'\\'\\'\\n%(r)s\\'\\'\\'\\n", {'tomllib': None, 'fallback': 'multi-line string'}),
    ('root = "%(r)s\\\\u0074"\\n', {'tomllib': 'does not exist', 'fallback': NOSAFE}),
    ('root = 5\\n', {'tomllib': 'has an unreadable root', 'fallback': 'has an unreadable root'}),
    ("version = 0x2\\nroot = '%(r)s'\\n", {'tomllib': None, 'fallback': NOSAFE}),
    ('root = "%(r)s" # say """ in a comment\\n', {'tomllib': None, 'fallback': 'multi-line string'}),
    ('imports = []\\nimports = []\\n', {'tomllib': 'is not valid TOML', 'fallback': 'sets imports 2 times'}),
    ('root = [\\n', {'tomllib': 'is not valid TOML', 'fallback': NOSAFE}),
])
def test_f1_containerd_config_refusals(F1, monkeypatch, parser, body, why):
    _parser(F1, monkeypatch, parser); _cfg(F1, body)
    if why[parser] is None: assert F1.measured() == F1.root(), body
    else: _refused(F1, why[parser])


@pytest.mark.parametrize('parser', PARSERS)
@pytest.mark.parametrize('body', ['"root" = "%(r)s"\\n', "'root' = '%(r)s'\\n"])
def test_f1_quoted_root_key_is_never_the_default_root(F1, monkeypatch, parser, body):
    """The receipt's reproducer: a valid quoted root key. tomllib reads the real root; the strict reader refuses."""
    _parser(F1, monkeypatch, parser); _cfg(F1, body)
    if parser == 'tomllib': assert F1.measured() == F1.root()
    else: _refused(F1, NOSAFE)


# `containerd config default` (v1.7, version 2): its top-level region and the start of its tables; and the config Docker's
# containerd.io package installs. Real-world configs both parsers must accept with the right root.
CTD_V2_DEFAULT = """disabled_plugins = []
imports = []
oom_score = 0
plugin_dir = ""
required_plugins = []
root = "%(r)s"
state = "/run/containerd"
temp = ""
version = 2

[cgroup]
  path = ""

[debug]
  address = ""
  format = ""
  gid = 0
  level = ""
  uid = 0

[grpc]
  address = "/run/containerd/containerd.sock"
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216
  tcp_address = ""
  uid = 0

[plugins]

  [plugins."io.containerd.gc.v1.scheduler"]
    deletion_threshold = 0
    mutation_threshold = 100
    pause_threshold = 0.02
    schedule_delay = "0s"
    startup_delay = "100ms"

  [plugins."io.containerd.grpc.v1.cri"]
    device_ownership_from_security_context = false
    sandbox_image = "registry.k8s.io/pause:3.8"
    root = "/var/lib/containerd/io.containerd.grpc.v1.cri"

  [plugins."io.containerd.snapshotter.v1.overlayfs"]
    mount_options = []
    root_path = ""
    sync_remove = false
"""
CTD_DOCKER_PACKAGE = """#   Copyright 2018-2022 Docker Inc.

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.

disabled_plugins = ["cri"]

#root = "/var/lib/containerd"
#state = "/run/containerd"
#subreaper = true
#oom_score = 0

#[grpc]
#  address = "/run/containerd/containerd.sock"
#  uid = 0
#  gid = 0

#[debug]
#  address = "/run/containerd/debug.sock"
#  uid = 0
#  gid = 0
#  level = "info"
"""


@pytest.mark.parametrize('parser', PARSERS)
def test_f1_real_world_containerd_configs_are_accepted_with_the_right_root(F1, monkeypatch, parser):
    _parser(F1, monkeypatch, parser)
    _cfg(F1, CTD_V2_DEFAULT); assert F1.measured() == F1.root()
    _cfg(F1, CTD_DOCKER_PACKAGE, sock='ctd2.sock', name='ctd2.toml')
    assert F1.measured() == F1.root('default-root'), 'every root line is commented out: the default root'


@pytest.mark.parametrize('body', [
    CTD_V2_DEFAULT, CTD_DOCKER_PACKAGE, "version = 2\\nroot = '%(r)s'   # the daemon root\\nimports = []\\n[plugins.x]\\n  root = '/elsewhere'\\n",
    "version = 2\\n[plugins.x]\\n  root = '%(r)s'\\n", "  root = '%(r)s'\\n\\n# c\\n", 'enabled = true\\nroot="%(r)s"#c\\n',
    "disabled_plugins = ['a', \\"b\\",]\\nroot = '%(r)s'\\n", "oom_score = -999\\nroot = '%(r)s'\\r\\n",
])
def test_f1_strict_reader_agrees_with_tomllib_whenever_it_accepts(F1, monkeypatch, body):
    """Parity: a config the strict reader accepts measures the same root as tomllib."""
    _cfg(F1, body); want = F1.measured()
    monkeypatch.setattr(F1.M, 'tomllib', None, raising=False)
    assert F1.measured() == want, body
''')
print('f1 tests applied')
