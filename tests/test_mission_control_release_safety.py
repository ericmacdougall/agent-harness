"""Formal F1-F4 controls; private synthetic state, no actual launchctl or credentials."""
import contextlib
import http.client
import io
import os
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mission_control_install as installer
from tests import test_mission_control as fixture

mcs = fixture.mcs
KEY = b"release-fixture-key" * 2


def code(auth, now=None):
    if hasattr(auth, "launch_generation"):
        return mcs.mint_code(KEY, auth.launch_generation, now=now)
    return mcs.mint_code(KEY, now=now)


class LaunchRestart(unittest.TestCase):
    def test_restart_refuses_redeemed_code_and_preserves_existing_session(self):
        with tempfile.TemporaryDirectory() as raw:
            store = Path(raw) / "sessions.json"
            first = mcs.Auth(lambda: KEY, 49999, store=store)
            token = code(first)
            sid = first.redeem(token)
            self.assertTrue(bool(sid))
            again = mcs.Auth(lambda: KEY, 49999, store=store)
            self.assertFalse(bool(again.redeem(token)), "restart accepted an old launch code")
            self.assertTrue(bool(again.session("mc_sid=" + sid)[0]), "existing session did not survive")

    def test_unredeemed_old_boot_and_unbound_legacy_tokens_refuse(self):
        first=mcs.Auth(lambda:KEY,49999);again=mcs.Auth(lambda:KEY,49999)
        self.assertFalse(bool(again.redeem(code(first))))
        payload=int(time.time()).to_bytes(8,'big')+b'x'*16
        legacy=mcs._b64(payload)+'.'+mcs._b64(mcs.hmac.new(KEY,b'mc-launch|'+payload,mcs.hashlib.sha256).digest()[:16])
        self.assertFalse(bool(again.redeem(legacy)))
        self.assertFalse(again.sessions)

    def test_generation_fetch_ignores_proxy_and_refuses_redirect_or_bad_schema(self):
        for status,raw in ((302,b'{}'),(200,b'[]'),(200,b'{"ok":true,"launch_generation":"bad"}')):
            connection=mock.Mock()
            connection.getresponse.return_value=SimpleNamespace(status=status,read=lambda n,data=raw:data)
            with mock.patch.dict(os.environ,{'HTTP_PROXY':'http://invalid-proxy','ALL_PROXY':'http://invalid-proxy'}), \
                 mock.patch.object(mcs.http.client,'HTTPConnection',return_value=connection) as connect, \
                 mock.patch.object(mcs.mc_chat,'secret',return_value=KEY):
                with self.assertRaises((ValueError,TypeError)):mcs.launch_url(47616)
            connect.assert_called_once_with('127.0.0.1',47616,timeout=3)
            self.assertEqual(connection.request.call_count,1)
            connection.close.assert_called_once()

    def test_demo_in_process_code_needs_no_listener(self):
        auth=mcs.Auth(lambda:KEY,47616)
        with mock.patch.object(mcs.http.client,'HTTPConnection',side_effect=AssertionError('unexpected connection')), \
             mock.patch.object(mcs.mc_chat,'secret',return_value=KEY):
            url=mcs.launch_url(47616,auth=auth)
        token=url.partition('?c=')[2]
        self.assertTrue(bool(auth.redeem(token)))


class StopTruth(unittest.TestCase):
    def test_failed_stop_loaded_job_missing_plist_is_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "absent.plist"
            def run(argv, **kwargs):
                return SimpleNamespace(returncode=5 if "bootout" in argv else 0,
                                       stdout="state = running\npid = 123\n", stderr="fixture stop refused")
            output = io.StringIO()
            with mock.patch.object(mcs, "plist_path", return_value=path), \
                 mock.patch.object(mcs.subprocess, "run", side_effect=run), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = mcs.cmd_uninstall(SimpleNamespace(apply=True))
            self.assertNotEqual(result, 0, "still-loaded job reported stopped")
            self.assertNotIn("uninstalled", output.getvalue())

    def test_absent_or_unknown_label_and_plist_unlink_errors_are_distinct(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'job.plist';path.write_text('owned')
            for state in ('unknown','absent'):
                with mock.patch.object(mcs,'plist_path',return_value=path), \
                     mock.patch.object(mcs,'loaded_label',return_value=(state,None)), \
                     mock.patch.object(Path,'unlink',side_effect=PermissionError('owned')), \
                     contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(mcs.cmd_uninstall(SimpleNamespace(apply=True)),0)
                self.assertTrue(path.exists())


class PublicationSafety(unittest.TestCase):
    def test_failed_final_rename_keeps_canonical_and_previous(self):
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            installer.install_app(home)
            app, previous = installer.app_dir(home), installer.mc_root(home) / "app.prev"
            (app / "fixture-active").write_text("active")
            previous.mkdir()
            (previous / "fixture-good").write_text("last-good")
            rename = os.rename
            def fail_final(source, target, *args, **kwargs):
                if Path(source).name.startswith(".app-") and Path(target).name == "app":
                    raise OSError("fixture final publication failure")
                return rename(source, target, *args, **kwargs)
            with mock.patch.object(installer.os, "rename", side_effect=fail_final):
                try:
                    installer.install_app(home)
                except OSError:
                    pass
            self.assertTrue((app / "server.py").is_file(), "canonical app disappeared")
            self.assertTrue((previous / "fixture-good").is_file(), "last rollback copy was discarded")

    def fixture_source(self, base, name, text):
        root=base/name
        (root/'web').mkdir(parents=True)
        (root/'server.py').write_text(text)
        (root/'web/index.html').write_text('<title>synthetic</title>')
        return root

    def test_unknown_component_walk_refuses_hash_and_publication(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);home=base/'home';home.mkdir()
            source=self.fixture_source(base,'source','synthetic')
            (source/'web/js').mkdir();(source/'web/js/main.js').write_text('synthetic')
            installer.install_app(home,source)
            app=installer.app_dir(home)
            original=os.scandir
            for kind in ('source','tree','digest','publication'):
                with self.subTest(kind=kind):
                    selected=source if kind in ('source','publication') else app
                    blocked=selected/'web/js'
                    def scandir(path):
                        if Path(path)==blocked:raise PermissionError('owned unknown walk')
                        return original(path)
                    with mock.patch.object(os,'scandir',side_effect=scandir):
                        with self.assertRaises(OSError):
                            if kind=='source':installer.source_files(source)
                            elif kind=='tree':installer._tree(app)
                            elif kind=='digest':mcs.component_digest(app)
                            else:installer.install_app(home,source)
                    self.assertEqual((app/'web/js/main.js').read_text(),'synthetic')

    def test_admitted_symlink_directory_is_refused_not_omitted(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);source=self.fixture_source(base,'source','synthetic')
            outside=base/'outside';outside.mkdir();(outside/'main.js').write_text('synthetic')
            (source/'web/js').symlink_to(outside,target_is_directory=True)
            for kind in ('source','digest','publication'):
                with self.subTest(kind=kind),self.assertRaises(OSError):
                    if kind=='source':installer.source_files(source)
                    elif kind=='digest':mcs.component_digest(source)
                    else:
                        home=base/'home';home.mkdir()
                        installer.install_app(home,source)

    def test_process_death_recovery_at_every_exchange_and_commit_boundary(self):
        for phase in ('prepared','after_exchange','published','verified','after_previous_retained','after_previous_promoted'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as raw:
                base=Path(raw);home=base/'home';home.mkdir()
                old=self.fixture_source(base,'old','old')
                new=self.fixture_source(base,'new','new')
                older=self.fixture_source(base,'older','older')
                installer.install_app(home,older)
                installer.install_app(home,old)
                prior=installer._tree(installer.mc_root(home)/'app.prev')
                script=('import sys,os;sys.path.insert(0,'+repr(str(fixture.REPO))+');'
                        'from pathlib import Path;import mission_control_install as m;'
                        'm.install_app(Path('+repr(str(home))+'),Path('+repr(str(new))+'),'
                        'fault=lambda p:os._exit(73) if p=='+repr(phase)+' else None)')
                child=subprocess.run([sys.executable,'-B','-c',script],capture_output=True,timeout=8)
                self.assertEqual(child.returncode,73)
                app=installer.app_dir(home)
                self.assertIn((app/'server.py').read_text(),('old','new'))
                with installer.install_lock(home):
                    installer._recover(home)
                if phase in ('prepared','after_exchange','published'):
                    self.assertEqual((app/'server.py').read_text(),'old')
                    self.assertEqual(installer._tree(installer.mc_root(home)/'app.prev'),prior)
                else:
                    self.assertEqual((app/'server.py').read_text(),'new')
                    self.assertEqual((installer.mc_root(home)/'app.prev/server.py').read_text(),'old')
                with installer.install_lock(home):
                    installer._recover(home)

    def test_repeated_activation_failure_preserves_old_active_and_previous(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);home=base/'home';home.mkdir()
            old=self.fixture_source(base,'old',"# --activation-id\nold")
            older=self.fixture_source(base,'older',"older")
            new=self.fixture_source(base,'new',"new")
            installer.install_app(home,older);installer.install_app(home,old)
            previous=installer._tree(installer.mc_root(home)/'app.prev')
            old_digest=installer._tree(installer.app_dir(home))['digest']
            for _ in range(2):
                with installer.install_lock(home), self.assertRaises(OSError):
                    installer._install_locked(home,new,lambda nonce:True,lambda digest,nonce:digest==old_digest)
                self.assertEqual((installer.app_dir(home)/'server.py').read_text(),'# --activation-id\nold')
                self.assertEqual(installer._tree(installer.mc_root(home)/'app.prev'),previous)

    def test_unknown_journal_and_unsupported_exchange_do_not_mutate(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);home=base/'home';home.mkdir();old=self.fixture_source(base,'old','old')
            new=self.fixture_source(base,'new','new');installer.install_app(home,old)
            before=installer._tree(installer.app_dir(home))
            with mock.patch.object(installer,'_exchange',side_effect=OSError('unsupported')):
                with self.assertRaises(OSError):installer.install_app(home,new)
            self.assertEqual(installer._tree(installer.app_dir(home)),before)
            value=json.loads((installer.mc_root(home)/installer.INSTALL_JOURNAL).read_text())
            value['phase']='FUTURE'
            (installer.mc_root(home)/installer.INSTALL_JOURNAL).write_text(json.dumps(value))
            with self.assertRaises(OSError):installer.install_app(home,new)
            self.assertEqual(installer._tree(installer.app_dir(home)),before)

    def test_real_cross_process_lock_serializes_installers(self):
        with tempfile.TemporaryDirectory() as raw:
            home=Path(raw);ready=home/'ready'
            script=('import sys;sys.path.insert(0,'+repr(str(fixture.REPO))+');'
                    'from pathlib import Path;import mission_control_install as m;'
                    'm.install_app(Path('+repr(str(home))+'));Path('+repr(str(ready))+').write_text("done")')
            with installer.install_lock(home):
                child=subprocess.Popen([sys.executable,'-B','-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    time.sleep(.15)
                    self.assertIsNone(child.poll())
                    self.assertFalse(ready.exists())
                finally:
                    pass
            output,error=child.communicate(timeout=8)
            self.assertEqual(child.returncode,0)
            self.assertTrue(ready.exists())

    def test_legacy_first_upgrade_failed_activation_retains_bytes_and_can_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);home=base/'home';home.mkdir()
            legacy=self.fixture_source(base,'legacy','legacy without new flags')
            new=self.fixture_source(base,'new','# --activation-id\nnew')
            installer.install_app(home,legacy)
            seen=[]
            def activate(nonce):
                seen.append(nonce)
                return nonce is None
            with installer.install_lock(home),self.assertRaises(OSError):
                installer._install_locked(home,new,activate,lambda digest,nonce:False)
            self.assertEqual((installer.app_dir(home)/'server.py').read_text(),'legacy without new flags')
            self.assertIn(None,seen)
            value=json.loads((installer.mc_root(home)/installer.INSTALL_JOURNAL).read_text())
            self.assertEqual(value['phase'],'ROLLED_BACK_LEGACY')
            with installer.install_lock(home):
                installer._install_locked(home,new,lambda nonce:True,lambda digest,nonce:True)
            self.assertEqual((installer.app_dir(home)/'server.py').read_text(),'# --activation-id\nnew')
            self.assertEqual((installer.mc_root(home)/'app.prev/server.py').read_text(),'legacy without new flags')

    def test_first_service_prepared_crash_recovers_before_normal_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw);home=base/'home';home.mkdir()
            source=self.fixture_source(base,'source','# --activation-id\nfirst')
            calls=[]
            def activate(nonce):calls.append(nonce);return True
            def fault(phase):
                if phase=='prepared':raise RuntimeError('owned first-service crash')
            with installer.install_lock(home),self.assertRaises(RuntimeError):
                installer._install_locked(home,source,activate,lambda digest,nonce:True,fault)
            self.assertFalse(installer.app_dir(home).exists())
            self.assertFalse(calls)
            with installer.install_lock(home):
                installer._install_locked(home,source,activate,lambda digest,nonce:True)
            self.assertEqual((installer.app_dir(home)/'server.py').read_text(),'# --activation-id\nfirst')
            self.assertEqual(len(calls),1)
            value=json.loads((installer.mc_root(home)/installer.INSTALL_JOURNAL).read_text())
            self.assertEqual(value['phase'],'COMMITTED')
            with installer.install_lock(home):installer._recover(home,activate,lambda digest,nonce:True)
            self.assertEqual(len(calls),1)

    def test_wrong_service_pid_digest_or_activation_nonce_cannot_verify(self):
        expected='a'*64;nonce='b'*32
        for change in ({'pid':124},{'component_digest':'c'*64},{'activation_id':'d'*32},{}):
            value={'ok':True,'pid':123,'component_digest':expected,'activation_id':nonce};value.update(change)
            connection=mock.Mock();connection.getresponse.return_value=SimpleNamespace(status=200,read=lambda n:json.dumps(value).encode())
            with mock.patch.object(installer,'_service_state',return_value=('loaded',123)), \
                 mock.patch.object(installer.http.client,'HTTPConnection',return_value=connection), \
                 mock.patch.object(installer.time,'sleep'):
                self.assertEqual(installer._verify_service(expected,nonce,lambda argv:None),not bool(change))


class InitialStreamFailure(unittest.TestCase):
    def test_header_failure_releases_attached_stream(self):
        hub = fixture.ev.Hub()
        auth = mcs.Auth(lambda: KEY, 49999)
        sid = auth.redeem(code(auth))
        handler = SimpleNamespace(app=SimpleNamespace(auth=auth, hub=hub, stop=threading.Event()), headers={},
            connection=SimpleNamespace(settimeout=lambda value: None),
            send_response=lambda status: (_ for _ in ()).throw(OSError("fixture headers failed")),
            send_header=lambda *args: None, end_headers=lambda: None, wfile=io.BytesIO())
        try:
            mcs.Handler.stream(handler, sid)
        except OSError:
            pass
        self.assertEqual(len(hub.clients), 0, "failed initial headers leaked stream slot")


class StalledStream(fixture.ServerHarness):
    def test_real_authenticated_nonreader_times_out_and_releases_both_slots(self):
        cookie,_=self.login()
        self.server.request_queue_size=4
        client=socket.socket();client.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024)
        client.settimeout(2);client.connect(('127.0.0.1',self.port));self.addCleanup(client.close)
        entered=threading.Event();blocked=threading.Event()
        original=mcs.Handler.stream
        def small_send(handler,sid):
            handler.connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,1024)
            return original(handler,sid)
        with mock.patch.object(mcs,'SSE_WRITE_TIMEOUT_S',.2),mock.patch.object(mcs.Handler,'stream',small_send):
            client.sendall(('GET /api/events HTTP/1.0\r\nHost: 127.0.0.1:'+str(self.port)+
                '\r\nCookie: '+cookie+'\r\nSec-Fetch-Site: same-origin\r\n\r\n').encode())
            deadline=time.monotonic()+2
            while not self.app.hub.clients and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(len(self.app.hub.clients),1)
            with self.app.hub.lock:
                self.app.hub.clients[0].push(b'data: '+b'x'*(2<<20)+b'\n\n')
            time.sleep(.05)
            self.assertEqual(len(self.app.hub.clients),1,'socket never reached a blocked write')
            deadline=time.monotonic()+2
            while (self.app.hub.clients or self.server.live) and time.monotonic()<deadline:time.sleep(.02)
            self.assertFalse(self.app.hub.clients)
            self.assertFalse(self.server.live)
            self.assertTrue(bool(self.app.auth.session(cookie)[0]))
            replacement=self.app.hub.attach();self.assertIsNotNone(replacement);self.app.hub.detach(replacement)
            healthy=http.client.HTTPConnection('127.0.0.1',self.port,timeout=2)
            try:
                with mock.patch.object(mcs,'SSE_HEARTBEAT_S',.05):
                    healthy.request('GET','/api/events',headers={'Cookie':cookie,'Sec-Fetch-Site':'same-origin'})
                    response=healthy.getresponse()
                    self.assertEqual(response.status,200)
                    self.assertEqual(response.fp.readline(),b'retry: 3000\n')
                    self.assertEqual(response.fp.readline(),b'\n')
                    self.assertEqual(response.fp.readline(),b': keepalive\n')
                    self.app.stop.set()
            finally:
                healthy.close()


if __name__ == "__main__":
    unittest.main()
