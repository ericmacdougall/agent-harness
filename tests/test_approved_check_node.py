"""GoodQA #15658: real nonempty Node checks through the shared delivery runner."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness/hooks'))
import integrate_local as il

class FocusedNode(unittest.TestCase):
    def test_exact_literal_forms_are_approved(self):
        for path in ('deploy/source-contract.test.mjs', 'a.test.js', 'test/a.test.cjs'):
            with self.subTest(path=path):
                self.assertTrue(il.approved_check(['node', '--test', path]))


import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
from unittest.mock import patch

WORK = Path.home() / '.agent-harness/work/focused-node-test-fixtures'
WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
GOOD = "import test from 'node:test'; import assert from 'node:assert/strict'; test('real',()=>assert.equal(2+2,4));\n"

class NodeProtocol(unittest.TestCase):
    def records(self):
        c = dict(tests=1, passed=1, failed=0, cancelled=0, skipped=0, todo=0, topLevel=1, suites=0)
        return [dict(kind='summary',file='/repo/a.test.mjs',success=True,counts=c),
                dict(kind='summary',file=None,success=True,counts=dict(c)),dict(kind='end')]

    def evidence(self, records, chunks=1):
        parser = il.NodeEvidence('/repo/a.test.mjs')
        data = b''.join((json.dumps(v)+'\n').encode() for v in records)
        for i in range(0,len(data),chunks): parser(data[i:i+chunks])
        return parser

    def test_complete_protocol_passes_at_chunk_boundaries(self):
        for size in (1,7,65536): self.assertTrue(self.evidence(self.records(),size).passed())

    def test_invalid_nonempty_or_conflicting_records_fail(self):
        mutations=[]
        for field,value in [('passed',0),('failed',1),('cancelled',1),('tests',True),('todo',-1),('tests',2),('topLevel',0)]:
            rs=copy.deepcopy(self.records()); rs[0]['counts'][field]=value; mutations.append(rs)
        for key,val in [('success',1),('file','/outside/a.test.mjs'),('counts',[]),('extra',True)]:
            rs=copy.deepcopy(self.records()); rs[0][key]=val; mutations.append(rs)
        rs=self.records(); rs[1]['counts']['passed']=2; mutations.append(rs)
        mutations.extend([self.records()[1:],self.records()[:-1],self.records()*2,
                          [self.records()[0],self.records()[0],self.records()[2]],
                          [dict(kind='diagnostic',text=json.dumps(self.records())),dict(kind='end')]])
        for records in mutations:
            with self.subTest(records=records): self.assertFalse(self.evidence(records).passed())

    def test_bad_json_oversized_and_truncated_eof_fail(self):
        for data in (b'not json\n',b'X'*20000,b'{"kind":"end"}',b'\xff\n'):
            p=il.NodeEvidence('/repo/a.test.mjs'); p(data); self.assertFalse(p.passed())
        p=self.evidence(self.records()); p(b'{'); self.assertFalse(p.passed())

    def test_diagnostics_cannot_mint_counts_and_are_redacted(self):
        seen=[]; p=il.NodeEvidence('/repo/a.test.mjs',seen.append)
        p((json.dumps(dict(kind='diagnostic',text='password=fictional-canary\n'+json.dumps(self.records())))+'\n').encode())
        self.assertFalse(p.passed()); self.assertNotIn(b'fictional-canary',b''.join(seen))

class NodePaths(unittest.TestCase):
    def test_unsafe_argv_and_paths_are_refused(self):
        for path in ('./a.test.mjs','../a.test.mjs','a/../b.test.js','/a.test.js','a//b.test.js','a\\b.test.js',
                     'a/*.test.js','a.test.js\n','-x.test.js','é.test.js','a.test.js;ls','a.test.js ','a.test.js\0',
                     'a.test.ts','a.test.js/', 'x'*129+'.test.js', 'a.test.js/**'):
            with self.subTest(path=repr(path)): self.assertFalse(il.approved_check(['node','--test',path]))
        for argv in (['/usr/bin/node','--test','a.test.js'],['node','--test','--test-reporter=tap','a.test.js'],
                     ['node','--test','a.test.js','b.test.js'],['node','--test','a.test.js','--'],['node','a.test.js']):
            self.assertFalse(il.approved_check(argv))

    def test_actual_path_must_be_regular_without_link_components(self):
        with tempfile.TemporaryDirectory(dir=WORK) as d:
            p=Path(d); (p/'a.test.mjs').write_text(GOOD); (p/'link.test.mjs').symlink_to(p/'a.test.mjs')
            (p/'directory.test.mjs').mkdir(); (p/'parent').symlink_to(p,target_is_directory=True)
            self.assertEqual(il.node_file(p,'a.test.mjs'),p/'a.test.mjs')
            for name in ('missing.test.mjs','link.test.mjs','parent/a.test.mjs','directory.test.mjs'):
                with self.subTest(name=name), self.assertRaises(OSError): il.node_file(p,name)
            (p/'a.test.mjs').unlink(); (p/'a.test.mjs').symlink_to('/dev/null')
            with self.assertRaises(OSError): il.node_file(p,'a.test.mjs')

    def test_interpreter_injection_missing_and_wrapper_fail(self):
        for key in ('NODE_OPTIONS','NODE_PATH','NODE_TEST_CONTEXT','NODE_V8_COVERAGE','NODE_TEST_REPORTER','LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','DYLD_INSERT_LIBRARIES'):
            with self.subTest(key=key),self.assertRaises(il.CheckInterpreterError): il.resolve_node({**os.environ,key:'fictional'})
        with tempfile.TemporaryDirectory(dir=WORK) as d:
            with self.assertRaises(il.CheckInterpreterError): il.resolve_node({'PATH':d})
            p=Path(d)/'node'; p.write_text('#!/bin/sh\necho "v26.10.0"\n'); p.chmod(0o700)
            with self.assertRaises(il.CheckInterpreterError): il.resolve_node({'PATH':d})

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX executable FIFO control')
    def test_executable_fifo_is_refused_before_open_or_version_child(self):
        with tempfile.TemporaryDirectory(dir=WORK) as d:
            root=Path(d); candidate=root/'node'; marker=root/'version-child-started'
            script = ("import sys,os; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                      "import integrate_local as i\n"
                      "def forbidden(*args,**kwargs):\n"
                      "    Path(sys.argv[3]).write_text('unexpected child'); raise AssertionError('version child started')\n"
                      "i.run_process=forbidden\n"
                      "original_open=os.open\n"
                      "def swapped(path,flags,*args,**kwargs):\n"
                      "    if Path(path)==Path(sys.argv[2])/'node':\n"
                      "        Path(path).unlink()\n"
                      "        if sys.argv[4]=='swap-fifo': os.mkfifo(path,0o700)\n"
                      "        else: Path(path).symlink_to('/dev/null')\n"
                      "    return original_open(path,flags,*args,**kwargs)\n"
                      "if sys.argv[4]!='fifo': i.os.open=swapped\n"
                      "try: i.resolve_node({'PATH':sys.argv[2]})\n"
                      "except i.CheckInterpreterError: sys.exit(0)\n"
                      "sys.exit(1)\n")
            for mode in ('fifo','swap-fifo','swap-link'):
                with self.subTest(mode=mode):
                    if candidate.exists() or candidate.is_symlink(): candidate.unlink()
                    if mode=='fifo': os.mkfifo(candidate,0o700)
                    else: candidate.write_bytes(b'\x7fELF0000'); candidate.chmod(0o700)
                    result=subprocess.run([sys.executable,'-c',script,str(Path(il.__file__).parent),str(root),str(marker),mode],
                                          capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which('node'),'real native executable required')
    def test_repo_path_directory_symlink_is_refused_but_external_alias_passes(self):
        native=Path(shutil.which('node')).resolve()
        with tempfile.TemporaryDirectory(dir=WORK) as d:
            root=Path(d); repo=root/'repo'; repo.mkdir()
            (repo/'bin').symlink_to(native.parent,target_is_directory=True)
            sibling=root/'sibling'; sibling.mkdir()
            for directory in (repo/'bin', sibling/'..'/'repo'/'bin'):
                with self.subTest(directory=str(directory)),self.assertRaises(il.CheckInterpreterError):
                    il.resolve_node({'PATH':str(directory)},repo)
            external=root/'external'; external.mkdir(); (external/'node').symlink_to(native)
            self.assertEqual(il.resolve_node({'PATH':str(external)},repo),str(native))

    @unittest.skipUnless(shutil.which('node'),'real native executable required')
    def test_old_silent_and_identity_mismatch_probes_are_refused(self):
        executable=str(Path(shutil.which('node')).resolve())
        for output in ('',json.dumps([executable,'20.12.0']),json.dumps(['/foreign/node','26.10.0'])):
            with self.subTest(output=output),patch.object(il,'run_process',return_value=subprocess.CompletedProcess([],0,output,'')):
                with self.assertRaises(il.CheckInterpreterError): il.resolve_node(dict(os.environ))

@unittest.skipUnless(shutil.which('node'),'real Node required')
class RealNode(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=WORK); self.addCleanup(self.temporary.cleanup)
        self.repo=Path(self.temporary.name)

    def run_body(self,body):
        (self.repo/'a.test.mjs').write_text(body)
        return il.run(self.repo,['node','--test','a.test.mjs'],timeout=30,discard_output=True).returncode

    def test_real_assertion_nested_mixed_and_filename_named_case_pass(self):
        self.assertEqual(self.run_body(GOOD),0)
        self.assertEqual(self.run_body("import test from 'node:test'; import assert from 'node:assert/strict'; test('suite',async t=>{await t.test('good',()=>assert.equal(1,1)); await t.test('skip',{skip:true},()=>{});});"),0)
        self.assertEqual(self.run_body("import test from 'node:test'; test(new URL(import.meta.url).pathname,()=>{});"),0)

    def test_empty_skipped_todo_suite_failed_exit_fake_output_fail(self):
        for body in ("import 'node:test';", "import {describe} from 'node:test'; describe('empty',()=>{});",
                     "import test from 'node:test'; test.skip('skip',()=>{});", "import test from 'node:test'; test.todo('todo');",
                     "import test from 'node:test'; test('bad',()=>{throw Error('intentional')});", 'process.exit(0);',
                     "import test from 'node:test'; test('not run',()=>{}); process.exit(0);",
                     "console.log('1..1\\n# tests 1\\n# pass 1'); console.error('{\"kind\":\"end\"}');",
                     "const c={tests:1,passed:1,failed:0,cancelled:0,skipped:0,todo:0,topLevel:1,suites:0}; for (const file of [import.meta.filename,null]) console.log(JSON.stringify({kind:'summary',file,success:true,counts:c})); console.log(JSON.stringify({kind:'end'}));"):
            with self.subTest(body=body): self.assertNotEqual(self.run_body(body),0)

    def test_cancellation_and_timeout_fail(self):
        self.assertNotEqual(self.run_body("import test from 'node:test'; const c=new AbortController(); c.abort(); test('cancelled',{signal:c.signal},()=>{});"),0)
        (self.repo/'a.test.mjs').write_text("setInterval(()=>{},1000);")
        with self.assertRaises(subprocess.TimeoutExpired):
            il.run(self.repo,['node','--test','a.test.mjs'],timeout=.3,discard_output=True)

    def test_real_capability_probe_and_foreign_repo_binary(self):
        with patch.object(il,'NODE_PROBE_DIRECTORY',self.repo/'private-probes'):
            il.require_check_interpreters([['node','--test','a.test.mjs']],self.repo)
        # A native Node copied into the reviewed repository is still a foreign interpreter.
        local=self.repo/'node'; shutil.copyfile(Path(shutil.which('node')).resolve(),local); local.chmod(0o700)
        with self.assertRaises(il.CheckInterpreterError): il.resolve_node({'PATH':str(self.repo)},self.repo)
        local.unlink(); local.symlink_to(Path(shutil.which('node')).resolve())
        with self.assertRaises(il.CheckInterpreterError): il.resolve_node({'PATH':str(self.repo)},self.repo)

    def test_missing_or_replaced_reporter_refuses_and_no_checkout_effect(self):
        import deliver
        for content in (None,b'// interrupted/replaced reporter\n'):
            with tempfile.TemporaryDirectory(dir=WORK) as d:
                sibling=Path(d)/'integrate_local.py'; sibling.write_text('')
                if content is not None: sibling.with_name('node_check_reporter.mjs').write_bytes(content)
                absent=self.repo/'absent'
                argv=['deliver.py','finish','--task','node-preflight','--original',str(absent),
                      '--original-branch','main','--mode','remote','--check','node --test a.test.mjs']
                with patch.object(il,'__file__',str(sibling)),patch.object(sys,'argv',argv):
                    with self.assertRaises(deliver.DeliveryError) as caught: deliver.finish(deliver.parse_args())
                self.assertEqual(caught.exception.status,'BLOCKED_POLICY'); self.assertFalse(absent.exists())

    def test_capability_failure_blocks_before_original_creation(self):
        import deliver
        absent=self.repo/'absent'
        argv=['deliver.py','finish','--task','node-capability','--original',str(absent),'--original-branch','main',
              '--mode','remote','--check','node --test a.test.mjs']
        with patch.object(sys,'argv',argv),patch.object(il,'run_node',return_value=subprocess.CompletedProcess([],0)):
            with self.assertRaises(deliver.DeliveryError): deliver.finish(deliver.parse_args())
        self.assertFalse(absent.exists())

    def test_real_js_and_cjs_assertions_pass(self):
        body = "const test=require('node:test'); const assert=require('node:assert/strict'); test('commonjs',()=>assert.equal(3*3,9));"
        for name in ('a.test.js','a.test.cjs'):
            (self.repo/name).write_text(body)
            self.assertEqual(il.run(self.repo,['node','--test',name],timeout=30,discard_output=True).returncode,0)

    def test_large_worker_diagnostic_stays_bounded_and_does_not_mint_evidence(self):
        seen=[]
        (self.repo/'a.test.mjs').write_text(GOOD+"console.log('z'.repeat(100000));")
        result=il.run(self.repo,['node','--test','a.test.mjs'],timeout=30,discard_output=True,sink=seen.append)
        self.assertEqual(result.returncode,0)
        self.assertLess(max(map(len,seen)),16384)

    def test_real_integration_selects_file_introduced_by_target_commit(self):
        import test_delivery_helpers as helpers
        with patch.object(tempfile,'tempdir',str(WORK)):
            fixture=helpers.DeliveryHelpers()
            try:
                fixture.setUp()
                selected=fixture.feature/'new.test.mjs'
                selected.write_text(GOOD)
                helpers.cmd('git','add','new.test.mjs',cwd=fixture.feature)
                helpers.cmd('git','commit','-qm','add focused Node assertion',cwd=fixture.feature)
                fixture.feature_head=helpers.cmd('git','rev-parse','HEAD',cwd=fixture.feature).stdout.strip()
                self.assertFalse((fixture.repo/'new.test.mjs').exists())
                argv=fixture.integrate_args('--timeout','30','--check-timeout','30')
                argv[argv.index('--check')+1]='node --test new.test.mjs'
                result=subprocess.run(argv,env=helpers.isolated_env(),capture_output=True,text=True,timeout=180)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'],'INTEGRATED')
                self.assertEqual((fixture.repo/'new.test.mjs').read_text(),GOOD)
                self.assertEqual(helpers.cmd('git','status','--porcelain',cwd=fixture.repo).stdout,'')
            finally:
                fixture.doCleanups()

    def test_real_delivery_checks_use_evidence(self):
        import deliver
        logs=self.repo/'logs'
        (self.repo/'a.test.mjs').write_text(GOOD)
        deliver.run_checks(self.repo,[],[['node','--test','a.test.mjs']],30,logs)
        (self.repo/'a.test.mjs').write_text("import 'node:test';")
        with self.assertRaises(deliver.DeliveryError): deliver.run_checks(self.repo,[],[['node','--test','a.test.mjs']],30,logs)
