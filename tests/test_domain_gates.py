"""Blockchain domain gates: detection, checklist data, spec_flow and peer_review hooks, opt-outs."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import domain_gates as dg  # noqa: E402
import peer_review as pr  # noqa: E402
import spec_flow as sf  # noqa: E402

ITEM_IDS = {"reentrancy", "access-control", "precision", "replay-chainid", "nonce-idempotency",
            "finality-reorg", "key-custody", "gas-dos", "upgradeability", "oracle-trust"}


def make_repo(files, symlinks=None):
    root = Path(tempfile.mkdtemp(prefix="dg-test-"))
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for name, target in (symlinks or {}).items():
        os.symlink(target, root / name)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def names(found):
    return {item["domain"] for item in found}


class DetectTests(unittest.TestCase):
    def test_signals(self):
        cases = {
            "evm": [{"src/A.sol": "contract A {}"}, {"foundry.toml": "[profile.default]"},
                    {"hardhat.config.ts": "export default {}"},
                    {"package.json": json.dumps({"dependencies": {"ethers": "^6"}})},
                    {"package.json": json.dumps({"devDependencies": {"viem": "2"}})},
                    {"package.json": json.dumps({"dependencies": {"web3": "4"}})}],
            "solana": [{"Anchor.toml": "[programs]"}, {"Cargo.toml": '[dependencies]\nanchor-lang = "0.30"\n'},
                       {"Cargo.toml": '[dependencies]\nsolana-program = "1.18"\n'}],
            "substrate": [{"Cargo.toml": '[dependencies]\nframe-support = { version = "1" }\n'},
                          {"Cargo.toml": '[dependencies]\nsp-runtime = "1"\n'},
                          {"Cargo.toml": '[dependencies]\npolkadot-sdk = "1"\n'}],
            "xrpl": [{"package.json": json.dumps({"dependencies": {"xrpl": "3"}})},
                     {"requirements.txt": "xrpl-py==2.5\n"},
                     {"package.json": json.dumps({"dependencies": {"ripple-lib": "1"}})}],
            "ledger-messaging": [{"api/ledger.proto": 'syntax = "proto3";', "go.mod": "require github.com/nats-io/nats.go v1\n"}],
        }
        for domain, variants in cases.items():
            for files in variants:
                with self.subTest(domain=domain, files=list(files)):
                    found = dg.detect(make_repo(files))
                    self.assertIn(domain, names(found))
                    item = [f for f in found if f["domain"] == domain][0]
                    self.assertTrue(item["evidence"])
                    self.assertIn(item["confidence"], ("high", "medium", "low"))

    def test_negative_repos_detect_nothing(self):
        for files in ({}, {"README.md": "ethers solidity anchor-lang"}, {"app.py": "print(1)"},
                      {"api/x.proto": "message A {}", "go.mod": "require github.com/nats-io/nats.go v1\n"},
                      {"package.json": json.dumps({"dependencies": {"react": "18"}})}):
            with self.subTest(files=list(files)):
                self.assertEqual(dg.detect(make_repo(files)), [])

    def test_proto_nats_needs_ledger_signal(self):
        plain = make_repo({"x.proto": "message Chat {}", "go.mod": "require nats.go v1\n"})
        self.assertEqual(dg.detect(plain), [])
        ledger = make_repo({"x.proto": "message Posting { int64 amount = 1; }", "go.mod": "require nats.go v1\n"})
        self.assertIn("ledger-messaging", names(dg.detect(ledger)))

    def test_changed_paths(self):
        repo = make_repo({"README.md": "x"})
        self.assertEqual(dg.detect(repo), [])
        found = dg.detect(repo, changed_paths=["contracts/Vault.sol"])
        self.assertIn("evm", names(found))
        self.assertTrue(any("diff" in e for e in found[0]["evidence"]))

    def test_symlinked_manifest_not_read(self):
        outside = Path(tempfile.mkdtemp()) / "package.json"
        outside.write_text(json.dumps({"dependencies": {"ethers": "6"}}))
        repo = make_repo({"README.md": "x"}, symlinks={"package.json": str(outside)})
        self.assertEqual(dg.detect(repo), [])

    def test_symlinked_directory_not_followed(self):
        outside = Path(tempfile.mkdtemp())
        (outside / "package.json").write_text(json.dumps({"dependencies": {"ethers": "6"}}))
        repo = make_repo({"README.md": "x"}, symlinks={"sub": str(outside)})
        self.assertEqual(dg.detect(repo), [])

    def test_oversized_manifest_ignored(self):
        big = json.dumps({"dependencies": {"ethers": "6"}, "pad": "x" * (dg.MAX_MANIFEST_BYTES + 10)})
        self.assertEqual(dg.detect(make_repo({"package.json": big})), [])

    def test_file_cap(self):
        files = {f"d{i:02d}/package.json": "{}" for i in range(30)}
        files["d29/package.json"] = json.dumps({"dependencies": {"ethers": "6"}})
        repo = make_repo(files)
        self.assertEqual(dg.detect(repo, max_files=5), [])  # the signal sorts past the cap
        self.assertIn("evm", names(dg.detect(repo, max_files=500)))  # positive control

    def test_vendored_dirs_skipped(self):
        for path in ("lib/forge-std/Test.sol", "node_modules/x/A.sol", "third_party/y/B.sol"):
            self.assertEqual(dg.detect(make_repo({path: "contract A {}"})), [], path)
        self.assertIn("evm", names(dg.detect(make_repo({"src/lib/Math.sol": "library M {}"}))))

    def test_deeply_nested_json_cannot_crash_the_interpreter(self):
        """5,000-deep JSON aborts CPython 3.9 (fatal recursion), so each case runs in a subprocess."""
        script = (
            "import json, subprocess, sys, tempfile, os\n"
            "sys.path.insert(0, %r)\n"
            "import domain_gates as dg\n"
            "deep = '[' * 5000 + ']' * 5000\n"
            "root = tempfile.mkdtemp(); subprocess.run(['git','init','-q',root], check=True)\n"
            "os.makedirs(root + '/.harness')\n"
            "open(root + '/package.json','w').write(deep)\n"
            "open(root + '/.harness/domain-gates.json','w').write(deep)\n"
            "subprocess.run(['git','-C',root,'add','-A'], check=True)\n"
            "found, ok = dg.detect_checked(root)\n"
            "assert found == [] and ok is False, (found, ok)\n"  # rejected manifest is a visible failure, not a pass
            "assert dg.repo_options(root) == {}\n"
            "try:\n"
            "    dg.safe_json_loads(deep)\n"
            "except ValueError as error:\n"
            "    assert 'nested' in str(error)\n"
            "else:\n"
            "    raise SystemExit('no ValueError')\n"
            "print('SURVIVED')\n" % str(HOOKS))
        done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, (done.returncode, done.stderr[-500:]))
        self.assertIn("SURVIVED", done.stdout)

    def test_not_a_repo_and_missing_dir(self):
        self.assertEqual(dg.detect(Path(tempfile.mkdtemp())), [])
        self.assertEqual(dg.detect(Path("/nonexistent/dg-none")), [])

    def test_evidence_is_sanitized(self):
        repo = make_repo({"a\x1b[31mevil.sol": "x"})
        for item in dg.detect(repo):
            for line in item["evidence"]:
                self.assertTrue(line.isprintable() and len(line) <= 160, line)


class ChecklistTests(unittest.TestCase):
    def test_every_domain_has_core_items(self):
        data = dg.load_checklists()
        for domain in ("evm", "solana", "substrate", "xrpl", "ledger-messaging"):
            items = dg.checklist(domain)
            self.assertTrue(items, domain)
            for item in items:
                self.assertTrue(item["id"] and item["title"] and item["neg"] and item["verify"], item)
                self.assertNotIn("{subject}", item["neg"])
                self.assertNotIn("{surface}", item["neg"])
            self.assertTrue(dg.scaffold(domain), domain)
            self.assertTrue(data["domains"][domain]["prompts"], domain)
        self.assertEqual({i["id"] for i in dg.checklist("evm")}, ITEM_IDS)

    def test_aliases_and_unknown(self):
        self.assertEqual(dg.resolve_domain("Solidity"), "evm")
        self.assertEqual(dg.resolve_domain("anchor"), "solana")
        with self.assertRaises(KeyError):
            dg.resolve_domain("cobol")

    def test_suggested_prompts(self):
        prompts = dg.suggested_prompts(["evm", "solana", "evm"])
        self.assertTrue(prompts)
        self.assertEqual(len(prompts), len(set(prompts)))
        self.assertEqual(dg.suggested_prompts([]), [])
        self.assertEqual(dg.suggested_prompts(["unknown"]), [])

    def test_block_contains_items_and_is_bounded(self):
        block = dg.render_block(["evm", "xrpl"])
        self.assertTrue(block.startswith("## Domain checklist"))
        for item_id in ITEM_IDS:
            self.assertIn(item_id, block)
        self.assertLess(len(block.encode()), 24000)
        self.assertEqual(dg.render_block([]), "")

    def test_corrupt_data_file_degrades(self):
        bad = Path(tempfile.mkdtemp()) / "c.json"
        bad.write_text("{not json")
        with mock.patch.object(dg, "CHECKLIST_FILE", bad):
            self.assertEqual(dg.checklist_or_empty("evm"), [])
            self.assertEqual(dg.render_block(["evm"]), "")


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = dg.main(list(argv))
        return code, out.getvalue()

    def test_detect_json(self):
        repo = make_repo({"foundry.toml": "x"})
        code, out = self.run_cli("detect", "--repo", str(repo), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)[0]["domain"], "evm")
        code, out = self.run_cli("detect", "--repo", str(make_repo({})))
        self.assertEqual(code, 0)
        self.assertIn("no blockchain", out.lower())

    def test_checklist_and_scaffold(self):
        code, out = self.run_cli("checklist", "--domain", "solana")
        self.assertEqual(code, 0)
        self.assertIn("access-control", out)
        code, out = self.run_cli("scaffold", "--domain", "xrpl")
        self.assertIn("ledger_accept", out)
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.run_cli("checklist", "--domain", "cobol")
        self.assertEqual(code, 2)


class OptOutTests(unittest.TestCase):
    def test_env_off(self):
        repo = make_repo({"foundry.toml": "x"})
        self.assertTrue(dg.active_domains(repo, env={}))
        for value in ("off", "OFF", "0", "false"):
            self.assertEqual(dg.active_domains(repo, env={"HARNESS_DOMAIN_GATES": value}), [])

    def test_policy_disabled(self):
        repo = make_repo({"foundry.toml": "x"})
        self.assertEqual(dg.active_domains(repo, policy={"domain_gates": {"disabled": True}}, env={}), [])
        self.assertTrue(dg.active_domains(repo, policy={"domain_gates": {"mode": "warn", "disabled": False}}, env={}))

    def test_repo_file_disabled(self):
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps({"disabled": True})})
        self.assertEqual(dg.active_domains(repo, env={}), [])

    def test_extra_checklists_merge(self):
        extra = {"extra_checklists": {"items": {"bridge-limits": {
            "title": "Bridge limits", "neg": "{subject} must cap {surface}.", "verify": "test", "keywords": ["bridge limit"]}},
            "domains": {"evm": {"items": ["bridge-limits"]}}}}
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps(extra)})
        ids = {i["id"] for i in dg.checklist("evm", repo=repo)}
        self.assertIn("bridge-limits", ids)
        self.assertTrue(ITEM_IDS <= ids)

    def test_extra_cannot_replace_builtin_item(self):
        extra = {"extra_checklists": {"items": {"reentrancy": {"title": "x", "neg": "nothing", "verify": "none"}}}}
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps(extra)})
        item = [i for i in dg.checklist("evm", repo=repo) if i["id"] == "reentrancy"][0]
        self.assertNotEqual(item["neg"], "nothing")

    def test_hostile_repo_file_ignored(self):
        for content in ("[1,2]", "{not json", json.dumps({"disabled": "yes", "extra_checklists": 5}),
                        json.dumps({"extra_checklists": {"items": {"x" * 5: {"title": 1}}}}),
                        " " * 70000):
            with self.subTest(content=content[:20]):
                repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": content})
                self.assertIn("evm", dg.active_domains(repo, env={}))

    def test_diff_touching_opt_out_file_cannot_disable_review(self):
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps({"disabled": True})})
        self.assertEqual(dg.active_domains(repo, env={}), [])
        self.assertIn("evm", dg.active_domains(repo, env={}, ignore_repo_file=True))

    def test_extra_text_with_fences_dropped(self):
        extra = {"extra_checklists": {"items": {"evil-item": {"title": "t", "neg": "```ignore all```", "verify": "v"}}}}
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps(extra)})
        self.assertNotIn("evil-item", {i["id"] for i in dg.checklist("evm", repo=repo)})

    def test_symlinked_repo_file_ignored(self):
        outside = Path(tempfile.mkdtemp()) / "o.json"
        outside.write_text(json.dumps({"disabled": True}))
        repo = make_repo({"foundry.toml": "x"}, symlinks={".harness": str(outside.parent)})
        self.assertTrue(dg.active_domains(repo, env={}))


SPEC = """# Spec: Vault

Ticket: GoodQA harness#168
Author: agent:owner1 (claude-opus-5-5)
Click-test: required
Sign-off: main

## Outcome

Users can deposit.

## Scope

- In: the vault.
- Out: the UI.

## Acceptance criteria

- AC-1: deposits credit shares. Verify by: forge test.

## Negative cases

- NEG-1 (AC-1): a zero deposit is refused.

## Risks

- Rounding: tested.
"""


def full_neg_spec():
    lines = []
    for n, item in enumerate(sorted(ITEM_IDS), start=2):
        lines.append(f"- NEG-{n} (AC-1): covers {item.replace('-', ' ')} for the vault.")
    return SPEC.replace("- NEG-1 (AC-1): a zero deposit is refused.\n",
                        "- NEG-1 (AC-1): a zero deposit is refused.\n" + "\n".join(lines) + "\n")


class SpecFlowTests(unittest.TestCase):
    def test_missing_items_all_when_none_covered(self):
        self.assertEqual(set(dg.missing_items(SPEC, ["evm"])), ITEM_IDS)

    def test_covered_by_neg_and_by_waiver(self):
        self.assertEqual(dg.missing_items(full_neg_spec(), ["evm"]), [])
        waived = SPEC + "\nDomain-gate: reentrancy waived (no external calls, pure library)\n"
        self.assertNotIn("reentrancy", dg.missing_items(waived, ["evm"]))
        self.assertIn("precision", dg.missing_items(waived, ["evm"]))

    def test_weak_waivers_do_not_count(self):
        for line in ("Domain-gate: reentrancy waived ()", "Domain-gate: reentrancy waived (<reason>)",
                     "Domain-gate: reentrancy waived (n/a)", "Domain-gate: waived (no reason for any item here)"):
            with self.subTest(line=line):
                self.assertIn("reentrancy", dg.missing_items(SPEC + "\n" + line + "\n", ["evm"]))

    def test_mention_inside_placeholder_or_other_section_does_not_count(self):
        text = SPEC.replace("a zero deposit is refused.", "a zero deposit is refused <reentrancy placeholder>.")
        self.assertIn("reentrancy", dg.missing_items(text, ["evm"]))
        text = SPEC.replace("- Rounding: tested.", "- reentrancy and precision: tested.")
        self.assertIn("reentrancy", dg.missing_items(text, ["evm"]))

    def test_new_appends_block_only_when_detected(self):
        out = Path(tempfile.mkdtemp()) / "s.md"
        evm_repo = make_repo({"foundry.toml": "x"})
        text = sf_template_text()
        with_block = sf.append_domain_block(text, evm_repo, {})
        self.assertIn("## Domain checklist", with_block)
        self.assertTrue(with_block.startswith(text))
        plain = sf.append_domain_block(text, make_repo({"a.txt": "x"}), {})
        self.assertEqual(plain, text)
        off = sf.append_domain_block(text, evm_repo, {"domain_gates": {"disabled": True}})
        self.assertEqual(off, text)
        self.assertFalse(out.exists())

    def test_block_does_not_break_lint_of_filled_spec(self):
        block = dg.render_block(["evm"])
        filled = full_neg_spec() + "\n" + block
        self.assertEqual(sf.lint(filled), [])

    def test_lint_warns_not_fails_by_default(self):
        repo = make_repo({"foundry.toml": "x"})
        warnings, problems = sf.domain_lint(SPEC, repo, {})
        self.assertTrue(any("reentrancy" in w for w in warnings))
        self.assertEqual(problems, [])

    def test_lint_enforce_mode_fails(self):
        repo = make_repo({"foundry.toml": "x"})
        warnings, problems = sf.domain_lint(SPEC, repo, {"domain_gates": {"mode": "enforce"}})
        self.assertTrue(problems)

    def test_lint_clean_spec_and_non_blockchain_repo_silent(self):
        repo = make_repo({"foundry.toml": "x"})
        self.assertEqual(sf.domain_lint(full_neg_spec(), repo, {}), ([], []))
        self.assertEqual(sf.domain_lint(SPEC, make_repo({"a.txt": "x"}), {}), ([], []))
        quiet = sf.domain_lint(SPEC, make_repo({"a.txt": "x"}), {"domain_gates": {"disabled": True}})
        self.assertEqual(quiet, ([], []))
        traced, _ = sf.domain_lint(SPEC, repo, {"domain_gates": {"disabled": True}})
        self.assertTrue(traced and "disabled by spec_policy.json" in traced[0])  # an opt-out leaves a trace

    def test_spec_block_domains_stay_binding(self):
        text = SPEC + "\n" + dg.render_block(["solana"])
        warnings, _ = sf.domain_lint(text, make_repo({"a.txt": "x"}), {})
        self.assertTrue(warnings)
        self.assertEqual(set(dg.missing_items(text, [])), {i["id"] for i in dg.checklist("solana")})  # block alone covers nothing

    def test_hostile_spec_is_fast(self):
        import time
        hostile = SPEC + "\n" + "## Domain checklist\n" * 40000
        started = time.monotonic()
        dg.missing_items(hostile, ["evm"])
        self.assertLess(time.monotonic() - started, 5)

    def test_decoy_generic_words_do_not_cover_items(self):
        decoy = SPEC.replace("a zero deposit is refused.", "secret redaction in logs; gas fee ui role label; db migration; "
                             "signature; confirmation dialog; rollback")
        self.assertEqual(set(dg.missing_items(decoy, ["evm"])), ITEM_IDS)

    def test_only_neg_bullets_count(self):
        text = SPEC.replace("- NEG-1 (AC-1): a zero deposit is refused.", "reentrancy and precision and access control\n- loose bullet about oracle")
        self.assertEqual(set(dg.missing_items(text, ["evm"])), ITEM_IDS)

    def test_waivers_in_fences_or_low_entropy_do_not_count(self):
        fenced = SPEC + "\n```\nDomain-gate: reentrancy waived (pure library, no calls)\n```\n"
        self.assertIn("reentrancy", dg.missing_items(fenced, ["evm"]))
        self.assertIn("reentrancy", dg.missing_items(SPEC + "\nDomain-gate: reentrancy waived (xxxxxxxxxxxx)\n", ["evm"]))

    def test_untracked_files_are_detected(self):
        repo = make_repo({"README.md": "x"})
        (repo / "New.sol").write_text("contract N {}")  # not added
        self.assertIn("evm", names(dg.detect(repo)))

    def test_not_a_git_checkout_warns_instead_of_silent_pass(self):
        warnings, _ = sf.domain_lint(SPEC, Path(tempfile.mkdtemp()), {})
        self.assertTrue(any("could not run" in w for w in warnings))

    def test_enforce_fails_closed_when_detection_cannot_run(self):
        enforce = {"domain_gates": {"mode": "enforce"}}
        _, problems = sf.domain_lint(SPEC, Path(tempfile.mkdtemp()), enforce)
        self.assertTrue(problems)
        repo = make_repo({"foundry.toml": "x"})
        with mock.patch.object(dg.subprocess, "run", return_value=mock.Mock(returncode=128, stdout=b"")):
            _, problems = sf.domain_lint(SPEC, repo, enforce)
            warnings, soft = sf.domain_lint(SPEC, repo, {})
        self.assertTrue(problems)
        self.assertTrue(warnings and not soft)

    def test_cargo_table_dependency_and_ledger_word_boundaries(self):
        self.assertIn("solana", names(dg.detect(make_repo({"Cargo.toml": '[dependencies.anchor-lang]\nversion = "0.30"\n'}))))
        lb = make_repo({"load_balancer.proto": "message A {}", "go.mod": "require nats.go v1\n"})
        self.assertEqual(dg.detect(lb), [])

    def test_enforce_applies_at_attach(self):
        spec = Path(tempfile.mkdtemp()) / "s.md"
        spec.write_text(SPEC)
        args = mock.Mock(spec=["spec", "repo"])
        args.spec, args.repo = str(spec), str(make_repo({"foundry.toml": "x"}))
        with mock.patch.object(sf, "ticket_config", return_value=(None, None, None)):
            with self.assertRaises(sf.SpecError) as ctx:
                sf.cmd_attach(args, {"domain_gates": {"mode": "enforce"}})
        self.assertIn("domain checklist items", str(ctx.exception))

    def test_packet_and_plain_lint_unaffected(self):
        repo = make_repo({"foundry.toml": "x"})
        self.assertEqual(sf.lint(SPEC), [])
        self.assertEqual(sf.lint(SPEC + "\n" + dg.render_block(["evm"])), [])

    def test_cmd_lint_prints_warnings_and_exit_unchanged(self):
        repo = make_repo({"foundry.toml": "x"})
        spec = Path(tempfile.mkdtemp()) / "s.md"
        spec.write_text(SPEC)
        args = mock.Mock(spec=["spec", "repo"], spec_path=None)
        args.spec, args.repo = str(spec), str(repo)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(sf, "ticket_config", return_value=(None, None, None)):
            code = sf.cmd_lint(args, {"domain_gates": {"mode": "warn"}})
        data = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(data["status"], "PASS")
        self.assertTrue(data["warnings"])


def sf_template_text():
    return (HOOKS / "spec_template.md").read_text().format(title="t", project="p", number=1, author="a", signoff="main")


class PeerReviewTests(unittest.TestCase):
    def test_section_is_bounded_and_marked(self):
        repo = make_repo({"foundry.toml": "x"})
        section, _ = pr.domain_section(repo, None)
        self.assertIn("Domain checklist", section)
        self.assertLessEqual(len(section.encode()), pr.DOMAIN_SECTION_LIMIT)
        self.assertEqual(pr.domain_section(make_repo({"a.txt": "x"}), None), ("", None))

    def test_opt_out_env(self):
        repo = make_repo({"foundry.toml": "x"})
        with mock.patch.dict(os.environ, {"HARNESS_DOMAIN_GATES": "off"}):
            section, source = pr.domain_section(repo, "b" * 40, changed_paths=[])
        self.assertEqual(section, "")
        self.assertIn("HARNESS_DOMAIN_GATES", source)

    def test_both_domains_keep_their_own_guidance(self):
        section = dg.packet_section(["evm", "solana"], None)
        self.assertIn("cross-program invocation", section)

    def test_repo_file_cannot_disable_or_extend_without_trusted_base(self):
        extra = {"disabled": True, "extra_checklists": {"items": {"my-item": {"title": "t", "neg": "{subject} injected text", "verify": "v"}}}}
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps(extra)})
        for base, paths in (("b" * 40, [".harness/domain-gates.json"]), (None, [])):
            section, source = pr.domain_section(repo, base, changed_paths=paths)
            self.assertIn("Domain checklist", section)
            self.assertNotIn("injected text", section)
            self.assertIsNone(source)
        section, source = pr.domain_section(repo, "b" * 40, changed_paths=["src/A.sol"])  # trusted: file existed before the diff
        self.assertEqual((section, source), ("", ".harness/domain-gates.json"))

    def test_peer_review_honours_policy_enforce_over_repo_file(self):
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps({"disabled": True})})
        with mock.patch.object(sf, "load_spec_policy", return_value={"domain_gates": {"mode": "enforce"}}):
            section, source = pr.domain_section(repo, "b" * 40, changed_paths=["src/A.sol"])
        self.assertIn("Domain checklist", section)
        with mock.patch.object(sf, "load_spec_policy", return_value={"domain_gates": {"disabled": True}}):
            section, source = pr.domain_section(repo, "b" * 40, changed_paths=["src/A.sol"])
        self.assertEqual(section, "")
        self.assertEqual(source, "spec_policy.json")

    def test_case_variant_opt_out_file_is_distrusted(self):
        repo = make_repo({"foundry.toml": "x"})
        section, source = pr.domain_section(repo, "b" * 40, changed_paths=[".HARNESS/Domain-Gates.json"])
        self.assertIn("Domain checklist", section)
        self.assertIsNone(source)

    def test_repo_file_cannot_switch_off_policy_enforce(self):
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps({"disabled": True})})
        self.assertTrue(dg.active_domains(repo, policy={"domain_gates": {"mode": "enforce"}}, env={}))
        self.assertEqual(dg.active_domains(repo, policy={"domain_gates": {"mode": "warn"}}, env={}), [])

    def test_enforce_fails_closed_on_broken_data(self):
        repo = make_repo({"foundry.toml": "x"})
        bad = Path(tempfile.mkdtemp()) / "c.json"
        bad.write_text("{not json")
        with mock.patch.object(dg, "CHECKLIST_FILE", bad):
            warnings, problems = sf.domain_lint(SPEC, repo, {"domain_gates": {"mode": "enforce"}})
            self.assertTrue(problems)
            warnings, problems = sf.domain_lint(SPEC, repo, {})
            self.assertEqual(problems, [])

    def test_go_mod_substring_is_not_a_dependency(self):
        self.assertEqual(dg.detect(make_repo({"go.mod": "require example.com/foo/web3stuff v1.0.0\n"})), [])
        self.assertIn("evm", names(dg.detect(make_repo({"go.mod": "require github.com/ethereum/go-ethereum v1.13.0\n"}))))

    def test_extra_scaffolds_validated_and_labelled(self):
        extra = {"extra_checklists": {"domains": {"evm": {"scaffolds": [
            {"id": "ok", "title": "mine", "commands": ["forge test"]}, {"title": "no id"},
            {"id": "x", "title": "t", "commands": ["a\x1bb"]}]}}}}
        repo = make_repo({"foundry.toml": "x", ".harness/domain-gates.json": json.dumps(extra)})
        ids = [s["id"] for s in dg.scaffold("evm", repo)]
        self.assertIn("ok", ids)
        self.assertNotIn("x", ids)
        self.assertTrue([s for s in dg.scaffold("evm", repo) if s["id"] == "ok"][0]["title"].startswith("[repo-supplied]"))

    def test_prompt_carries_section_without_touching_packet(self):
        captured = {}

        def fake_run(cmd, prompt, cwd, timeout):
            captured["prompt"] = prompt
            return 0, "", ""
        options = {"domain_section": "## Domain checklist\n- reentrancy"}
        with mock.patch.object(pr, "run", fake_run), mock.patch.object(pr.shutil, "which", return_value="/x"), \
                mock.patch.object(pr, "normalize_provider", return_value={
                    "result": "PASS", "report": "PLAN_RESULT: ACCEPT", "reason": "OK", "fallback_allowed": False,
                    "account_cooldown": None, "reset_at": None, "usage": None}), \
                mock.patch.object(pr, "stage_report", side_effect=lambda s, r: r):
            pr.review_snapshot(Path(tempfile.mkdtemp()), "a" * 40, "plan", "rules", "PACKET-BYTES", options)
        self.assertIn("PACKET-BYTES", captured["prompt"])
        self.assertIn("Domain checklist", captured["prompt"])
        self.assertLess(captured["prompt"].index("PACKET-BYTES"), captured["prompt"].index("Domain checklist"))


class Py39Tests(unittest.TestCase):
    def test_module_uses_lazy_annotations(self):
        self.assertIn("from __future__ import annotations", (HOOKS / "domain_gates.py").read_text())

    def test_installers_ship_the_files(self):
        root = HOOKS.parents[1]
        for installer in ("install.py", "install_codex.py"):
            text = (root / installer).read_text()
            for name in ("domain_gates.py", "domain_checklists.json"):
                self.assertIn(name, text, (installer, name))


if __name__ == "__main__":
    unittest.main()
