"""goodqa#16148 code review F3: NEG-18 cluster forms. Run in infra/selfhost/app."""
p = 'test_cmdline_sampler.py'
s = open(p).read()
anchor = "    def test_neg18_other_cgroup_is_not_sampled(self):\n"
new = '''    def test_neg18_clustered_short_flags_with_e_fail(self):
        # F3: pflag accepts clustered shorthands, so -de K=V and -ieK=V carry an env value too.
        for argv in (['docker', 'run', '-de', 'K=' + MARKER, 'img'],
                     ['docker', 'run', '-ieK=' + MARKER, 'img'],
                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img']):
            shutil.rmtree(self.proc)
            os.makedirs(self.proc)
            self.add(argv)
            out, code = self.sample('--expect-runs', '1')
            self.assertEqual((out['verdict'], code), ('FAIL', 1), argv[2])
            self.assertEqual(out['runs_with_env_flag'], 1)
            text = json.dumps(out)
            for i in range(0, len(MARKER) - 7):
                self.assertNotIn(MARKER[i:i + 8], text)

    def test_clusters_without_an_env_flag_still_pass(self):
        # Booleans only, and an e that is part of a value-taking flag's value (-w example), are not env flags.
        self.add(['docker', 'run', '-dit', '-wexample', '--env-file', '/x', 'img'])
        out, code = self.sample('--expect-runs', '1')
        self.assertEqual((out['verdict'], code), ('PASS', 0))
        self.assertEqual(out['runs'][0]['flags'], ['-d(attached)', '-(other)(attached)', '--env-file'])

'''
assert s.count(anchor) == 1
s = s.replace(anchor, new + anchor)
open(p, 'w').write(s)
print('tests patched')
