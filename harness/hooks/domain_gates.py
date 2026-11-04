#!/usr/bin/env python3
"""Blockchain domain gates: detect blockchain work, then supply risk checklists, test scaffolds and prompts.

All guidance text lives in domain_checklists.json. Detection reads only file names from `git ls-files`
(capped) plus a few small manifests, never follows symlinks, and never executes anything from the repo.
Opt out with HARNESS_DOMAIN_GATES=off, `"domain_gates": {"disabled": true}` in spec_policy.json, or
`.harness/domain-gates.json` with {"disabled": true} in the repo. Repo-supplied "extra_checklists" may add
items but never replace a built-in one.

Commands: detect --repo R [--json] | checklist --domain D | scaffold --domain D
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKLIST_FILE = HERE / "domain_checklists.json"
OPT_OUT_FILE = ".harness/domain-gates.json"
MAX_FILES = 20000
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFESTS = 200
MAX_TOTAL_READ = 4 * 1024 * 1024
MAX_PROTO_FILES = 20
MAX_PROTO_BYTES = 64 * 1024
MAX_OPT_OUT_BYTES = 64 * 1024
MAX_CHECKLIST_BYTES = 512 * 1024
MAX_EVIDENCE = 5
EVIDENCE_CHARS = 160
MAX_EXTRA_ITEMS = 20
MAX_EXTRA_TEXT = 1000
DISABLE_VALUES = {"off", "0", "false", "no", "disabled"}
CORE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")

HARDHAT = re.compile(r"^hardhat\.config\.(js|cjs|mjs|ts|cts|mts)$")
MANIFESTS = {"package.json", "Cargo.toml", "go.mod", "pyproject.toml", "foundry.toml"}
REQUIREMENTS = re.compile(r"^requirements[A-Za-z0-9._-]*\.txt$")
LEDGER_WORDS = re.compile(r"(?i)(?<![a-z])(?:ledger|journal|posting|balance)s?(?![a-z])")
NATS_NAMES = ("nats", "nats.go", "nats-io", "async-nats", "nats-py", "nats.js", "nats.ws", "nats.deno", "nats.net")
# (domain, confidence, needle). A needle matches a dependency name in a manifest.
DEPENDENCIES = (
    ("evm", "medium", ("ethers", "viem", "web3", "wagmi", "@openzeppelin/contracts", "hardhat", "web3.py", "eth-brownie",
                       "go-ethereum", "ethers-rs", "alloy", "foundry-rs", "py-evm", "eth-account")),
    ("solana", "high", ("anchor-lang", "solana-program", "anchor-spl", "solana-sdk", "@coral-xyz/anchor", "@solana/web3.js", "anchorpy")),
    ("substrate", "high", ("frame-support", "frame-system", "sp-runtime", "polkadot-sdk", "sp-core", "@polkadot/api", "substrate-interface")),
    ("xrpl", "high", ("xrpl", "xrpl-py", "xrpl-rust", "ripple-lib", "ripple-keypairs")),
)


def _clean(text, limit=EVIDENCE_CHARS):
    """Evidence and repo-supplied text: no control characters, backticks or fences, bounded length."""
    return re.sub(r"[^A-Za-z0-9._/@:+()#, -]", "?", str(text))[:limit]


def _read_small(root: Path, rel: str, limit: int, budget=None):
    """Read one regular file inside root without following symlinks; None when unsafe or too large."""
    try:
        path = root / rel
        if os.path.realpath(path) != os.path.join(os.path.realpath(root), *Path(rel).parts):
            return None  # a component is a symlink or the path escapes the repo
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink > 50:
            return None
        if budget is not None:
            if budget[0] + info.st_size > MAX_TOTAL_READ:
                return None
            budget[0] += info.st_size
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode("utf-8", "replace") if total <= limit else None
    except OSError:
        return None
    finally:
        os.close(fd)


SIGNAL_PATHSPECS = ("*.sol", "*foundry.toml", "*hardhat.config.*", "*Anchor.toml", "*package.json", "*Cargo.toml",
                    "*go.mod", "*pyproject.toml", "*requirements*.txt", "*.proto",
                    ":(icase)*ledger*", ":(icase)*journal*", ":(icase)*posting*", ":(icase)*balance*")
SKIP_COMPONENTS = {"node_modules", "vendor", "third_party", "testdata", "fixtures", ".git"}


def _skipped(path: str) -> bool:
    parts = path.split("/")
    return bool(SKIP_COMPONENTS.intersection(parts[:-1])) or (len(parts) > 1 and parts[0] == "lib")


def _tracked_files(root: Path, max_files: int):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        done = subprocess.run(["git", "-C", str(root), "-c", "core.fsmonitor=false", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *SIGNAL_PATHSPECS],
                              capture_output=True, timeout=15, env=env)
    except (OSError, subprocess.SubprocessError):
        return []
    if done.returncode:
        return []
    names = [n.decode("utf-8", "replace") for n in done.stdout[:8_000_000].split(b"\0") if n]
    return [n for n in sorted(names) if not _skipped(n)][:max_files]


def _dep_present(text: str, name: str, kind: str) -> bool:
    if kind == "package.json":
        return name in _package_deps(text)
    if kind == "go.mod":
        return re.search(r"(?m)^\s*(?:require\s+)?(?:\S*/)?" + re.escape(name) + r"(?:/\S*)?\s+v\d", text) is not None
    if re.search(r"(?m)^\s*\[[\w.-]*dependencies\." + re.escape(name) + r"\]", text):
        return True
    pattern = r"(?im)^\s*[\"']?" + re.escape(name) + r"[\"']?\s*(?:[=<>~!\[;{]|$)"
    return re.search(pattern, text) is not None


def _package_deps(text: str) -> set:
    try:
        data = json.loads(text)
    except Exception:  # deeply nested input raises RecursionError, not ValueError
        return set()
    found = set()
    if isinstance(data, dict):
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if isinstance(data.get(key), dict):
                found.update(str(k) for k in data[key])
    return found


class _Found:
    def __init__(self):
        self.domains = {}

    def add(self, domain, confidence, evidence):
        entry = self.domains.setdefault(domain, {"domain": domain, "confidence": confidence, "evidence": []})
        rank = {"low": 0, "medium": 1, "high": 2}
        if rank[confidence] > rank[entry["confidence"]]:
            entry["confidence"] = confidence
        text = _clean(evidence)
        if text not in entry["evidence"] and len(entry["evidence"]) < MAX_EVIDENCE:
            entry["evidence"].append(text)

    def result(self):
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(self.domains.values(), key=lambda e: (order[e["confidence"]], e["domain"]))


def _base(path: str) -> str:
    return path.rsplit("/", 1)[-1][:40]  # evidence names files by base name only: paths are repo-controlled text


def _path_signals(path: str, found: _Found, tag: str):
    base = path.rsplit("/", 1)[-1]
    if base.endswith(".sol"):
        found.add("evm", "high", f"{tag}solidity file {_base(path)}")
    if base == "foundry.toml":
        found.add("evm", "high", f"{tag}foundry.toml")
    if HARDHAT.match(base):
        found.add("evm", "high", f"{tag}hardhat config {_base(path)}")
    if base == "Anchor.toml":
        found.add("solana", "high", f"{tag}Anchor.toml")


def detect(repo, changed_paths=None, max_files: int = MAX_FILES) -> list:
    """Return [{domain, confidence, evidence[]}] from tracked files, small manifests and changed paths."""
    found = _Found()
    try:
        root = Path(repo).resolve()
        if not root.is_dir():
            return []
    except OSError:
        return []
    for path in list(changed_paths or [])[:max_files]:
        if isinstance(path, str) and path and "\0" not in path:
            _path_signals(path, found, "diff: ")
    files = _tracked_files(root, max_files)
    budget, manifests, protos, nats_in, ledger_in = [0], 0, 0, [], []
    for path in files:
        _path_signals(path, found, "")
        base = path.rsplit("/", 1)[-1]
        if LEDGER_WORDS.search(path):
            ledger_in.append(path)
        if base in MANIFESTS or REQUIREMENTS.match(base):
            if manifests >= MAX_MANIFESTS:
                continue
            manifests += 1
            text = _read_small(root, path, MAX_MANIFEST_BYTES, budget)
            if text is None:
                continue
            kind = base if base in MANIFESTS else "requirements.txt"
            for domain, confidence, names in DEPENDENCIES:
                for name in names:
                    if _dep_present(text, name, kind):
                        found.add(domain, confidence, f"dependency {name} in {_base(path)}")
            for name in NATS_NAMES:
                if kind != "foundry.toml" and _dep_present(text, name, kind):
                    nats_in.append(f"{name} in {_base(path)}")
                    break
        elif base.endswith(".proto"):
            protos += 1
            if protos <= MAX_PROTO_FILES:
                text = _read_small(root, path, MAX_PROTO_BYTES, budget)
                if text is not None and LEDGER_WORDS.search(text):
                    ledger_in.append(path)
    proto_paths = [p for p in files if p.endswith(".proto")]
    if proto_paths and nats_in and ledger_in:
        found.add("ledger-messaging", "medium", f"proto {_base(proto_paths[0])} + nats ({nats_in[0]}) + ledger signal ({_base(ledger_in[0])})")
    return found.result()


# --------------------------------------------------------------------------- data

def load_checklists() -> dict:
    """Load and shape-check the shipped checklist file; raises ValueError when unusable."""
    data = _load_json(CHECKLIST_FILE, MAX_CHECKLIST_BYTES)
    if not isinstance(data, dict) or not isinstance(data.get("items"), dict) or not isinstance(data.get("domains"), dict):
        raise ValueError("domain checklist file has the wrong shape")
    return data


def _load_json(path: Path, limit: int):
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f"{path.name} is not a regular file of at most {limit} bytes")
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {path.name}: {error}")


def _text(value, limit=MAX_EXTRA_TEXT):
    return isinstance(value, str) and 0 < len(value) <= limit and "```" not in value and value.isprintable()


def repo_options(repo, ignore: bool = False) -> dict:
    """Parse .harness/domain-gates.json defensively; anything odd yields {}."""
    if repo is None or ignore:
        return {}
    text = _read_small(Path(repo).resolve(), OPT_OUT_FILE, MAX_OPT_OUT_BYTES)
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    options = {}
    if data.get("disabled") is True:
        options["disabled"] = True
    extra = data.get("extra_checklists")
    if isinstance(extra, dict):
        options["extra"] = _valid_extra(extra)
    return options


def _scaffold(value):
    if not (isinstance(value, dict) and _text(value.get("id"), 60) and _text(value.get("title"), 200)):
        return None
    commands = value.get("commands", [])
    if not isinstance(commands, list) or not all(_text(c, 300) for c in commands):
        return None
    out = {"id": value["id"], "title": "[repo-supplied] " + value["title"], "commands": commands[:10]}
    if _text(value.get("notes")):
        out["notes"] = value["notes"]
    return out


def _valid_extra(extra: dict) -> dict:
    items, domains = {}, {}
    for ident, item in list(extra.get("items", {}).items() if isinstance(extra.get("items"), dict) else [])[:MAX_EXTRA_ITEMS]:
        if (isinstance(ident, str) and CORE_ID.match(ident) and isinstance(item, dict)
                and all(_text(item.get(k)) for k in ("title", "neg", "verify"))):
            keywords = item.get("keywords", [])
            items[ident] = {"title": "[repo-supplied] " + item["title"], "neg": item["neg"], "verify": item["verify"],
                            "keywords": [k for k in keywords if _text(k, 60)][:10] if isinstance(keywords, list) else []}
    for name, domain in list(extra.get("domains", {}).items() if isinstance(extra.get("domains"), dict) else [])[:10]:
        if not (isinstance(name, str) and CORE_ID.match(name) and isinstance(domain, dict)):
            continue
        listed = domain.get("items", [])
        clean = {"items": [i for i in listed if isinstance(i, str) and CORE_ID.match(i)][:MAX_EXTRA_ITEMS]
                 if isinstance(listed, list) else []}
        for key in ("title", "subject", "surface"):
            if _text(domain.get(key), 200):
                clean[key] = domain[key]
        prompts = domain.get("prompts")
        if isinstance(prompts, list):
            clean["prompts"] = [v for v in prompts if _text(v)][:10]
        scaffolds = domain.get("scaffolds")
        if isinstance(scaffolds, list):
            clean["scaffolds"] = [_scaffold(v) for v in scaffolds[:10] if _scaffold(v)]
        domains[name] = clean
    return {"items": items, "domains": domains}


def merged_data(repo=None, extra=None, ignore_repo_file: bool = False) -> dict:
    data = json.loads(json.dumps(load_checklists()))
    extra = extra if extra is not None else repo_options(repo, ignore_repo_file).get("extra") or {}
    for ident, item in extra.get("items", {}).items():
        data["items"].setdefault(ident, item)  # a repo can add items, never weaken a built-in one
    for name, domain in extra.get("domains", {}).items():
        target = data["domains"].setdefault(name, {"title": name, "subject": "the system", "surface": "each changed behavior",
                                                     "items": [], "overrides": {}, "scaffolds": [], "prompts": []})
        for ident in domain.get("items", []):
            if ident in data["items"] and ident not in target["items"]:
                target["items"].append(ident)
        for key in ("scaffolds", "prompts"):
            target.setdefault(key, [])
            target[key].extend(domain.get(key, []))
    return data


def resolve_domain(name: str, data=None) -> str:
    data = data or load_checklists()
    key = str(name).strip().lower()
    key = data.get("aliases", {}).get(key, key)
    if key not in data["domains"]:
        raise KeyError(f"unknown domain {name!r}; known: {', '.join(sorted(data['domains']))}")
    return key


def checklist(domain: str, repo=None, data=None) -> list:
    data = data or merged_data(repo)
    key = resolve_domain(domain, data)
    spec = data["domains"][key]
    out = []
    for ident in spec.get("items", []):
        base = data["items"].get(ident)
        if not base:
            continue
        item = {**base, **spec.get("overrides", {}).get(ident, {})}
        fill = {"{subject}": spec.get("subject", "the system"), "{surface}": spec.get("surface", "each changed behavior")}
        neg = item["neg"]
        for token, value in fill.items():
            neg = neg.replace(token, value)
        out.append({"id": ident, "title": item["title"], "neg": neg, "neg_raw": item["neg"], "verify": item["verify"],
                    "keywords": list(base.get("keywords", [])) + list(item.get("keywords", []))})
    return out


def checklist_or_empty(domain: str, repo=None) -> list:
    try:
        return checklist(domain, repo)
    except (ValueError, KeyError):
        return []


def scaffold(domain: str, repo=None) -> list:
    data = merged_data(repo)
    return list(data["domains"][resolve_domain(domain, data)].get("scaffolds", []))


def suggested_prompts(domains) -> list:
    """Follow-up prompts for the given domains (names or aliases), deduplicated, unknown names skipped."""
    try:
        data = load_checklists()
    except ValueError:
        return []
    seen, out = set(), []
    for name in domains or []:
        try:
            key = resolve_domain(name, data)
        except KeyError:
            continue
        for prompt in data["domains"][key].get("prompts", []):
            if prompt not in seen:
                seen.add(prompt)
                out.append(prompt)
    return out


# --------------------------------------------------------------------------- settings

def settings(repo=None, policy=None, env=None, ignore_repo_file: bool = False) -> dict:
    env = os.environ if env is None else env
    config = (policy or {}).get("domain_gates")
    config = config if isinstance(config, dict) else {}
    mode = config.get("mode") if config.get("mode") in ("warn", "enforce") else "warn"
    disabled = (str(env.get("HARNESS_DOMAIN_GATES", "")).strip().lower() in DISABLE_VALUES
                or config.get("disabled") is True or repo_options(repo, ignore_repo_file).get("disabled") is True)
    source = ("env HARNESS_DOMAIN_GATES" if str(env.get("HARNESS_DOMAIN_GATES", "")).strip().lower() in DISABLE_VALUES
              else "spec_policy.json" if config.get("disabled") is True else OPT_OUT_FILE)
    return {"disabled": disabled, "mode": mode, "source": source if disabled else None}


def is_git_repo(repo) -> bool:
    try:
        done = subprocess.run(["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"], capture_output=True, timeout=10,
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_GLOBAL": os.devnull})
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def active_domains(repo, policy=None, changed_paths=None, env=None, ignore_repo_file: bool = False) -> list:
    """Detected canonical domain names, or [] when disabled or nothing is detected."""
    if settings(repo, policy, env, ignore_repo_file)["disabled"]:
        return []
    return [item["domain"] for item in detect(repo, changed_paths)]


# --------------------------------------------------------------------------- rendering and matching

def render_block(domains, repo=None, detected=None) -> str:
    """The `## Domain checklist` spec block; '' when no usable domain or the data file is broken."""
    try:
        data = merged_data(repo)
        keys = []
        for name in domains or []:
            key = resolve_domain(name, data)
            if key not in keys:
                keys.append(key)
        lines = []
        for key in keys:
            lines.append(f"### {data['domains'][key].get('title', key)} ({key})")
            for item in checklist(key, data=data):
                lines.append(f"- {item['id']}: {item['title']}. NEG: {item['neg']} Verify by: {item['verify']}")
    except (ValueError, KeyError):
        return ""
    if not keys:
        return ""
    head = ["## Domain checklist", "", f"Domains: {', '.join(keys)}", ""]
    if detected:
        head += ["Detected from: " + "; ".join(_clean(e, 100) for d in detected for e in d.get("evidence", [])[:2])[:400], ""]
    head += ["Cover each item below with a NEG case in the Negative cases section that names it, or waive it with one line",
             "`Domain-gate: <item-id> waived (<reason, 10+ chars>)`. Delete items that do not apply only by waiving them.", ""]
    return "\n".join(head + lines) + "\n"


def spec_domains(spec_text: str) -> list:
    """Domains named by the first `## Domain checklist` block (line-based: hostile specs cannot make it slow)."""
    lines = spec_text.split("\n")
    for index, line in enumerate(lines):
        if line.rstrip() == "## Domain checklist":
            for follow in lines[index + 1:index + 6]:
                if follow.startswith("Domains:"):
                    return [d.strip() for d in follow[len("Domains:"):].split(",") if d.strip()][:10]
            return []
    return []


def _negative_text(spec_text: str) -> str:
    """Bodies of `- NEG-n (AC-n): ...` bullets in the Negative cases section, placeholders removed."""
    inside, found = False, []
    for line in spec_text.split("\n"):
        if line.startswith("## "):
            inside = line.rstrip() == "## Negative cases"
        elif inside and re.match(r"^- NEG-\d+\s*\([^)]*\):\s*\S", line):
            found.append(line)
    return re.sub(r"<[^<>\n]*>", " ", "\n".join(found)).lower().replace("-", " ")


def _keyword_hit(text: str, keyword: str) -> bool:
    word = keyword.lower().replace("-", " ").strip()
    if not word:
        return False
    pattern = r"(?<![a-z0-9])" + re.escape(word) + (r"(?![a-z0-9])" if len(word) <= 4 else "")
    return re.search(pattern, text) is not None


WAIVER = re.compile(r"(?m)^Domain-gate:[ \t]*([a-z0-9-]+)[ \t]+waived[ \t]*\(([^()\n]*)\)[ \t]*$")


def waived_items(spec_text: str) -> set:
    unfenced, fenced = [], False
    for line in spec_text.split("\n"):
        if line.startswith("```") or line.startswith("~~~"):
            fenced = not fenced
        elif not fenced:
            unfenced.append(line)
    return {m.group(1) for m in WAIVER.finditer("\n".join(unfenced))
            if len(m.group(2).strip()) >= 10 and "<" not in m.group(2) and len(set(m.group(2).lower())) >= 6}


def missing_items(spec_text: str, domains, repo=None) -> list:
    """Checklist item ids with neither a NEG case naming them nor a valid waiver line."""
    try:
        data = merged_data(repo)
        keys = []
        for name in list(domains or []) + spec_domains(spec_text):
            try:
                key = resolve_domain(name, data)
            except KeyError:
                continue
            if key not in keys:
                keys.append(key)
        negatives, waived, missing = _negative_text(spec_text), waived_items(spec_text), []
        for key in keys:
            for item in checklist(key, data=data):
                if item["id"] in missing or item["id"] in waived:
                    continue
                words = [item["id"]] + item["keywords"]
                if not any(_keyword_hit(negatives, w) for w in words):
                    missing.append(item["id"])
        return missing
    except (ValueError, KeyError):
        return []


def packet_section(domains, repo=None, limit: int = 9000, ignore_repo_file: bool = False) -> str:
    """Compact reviewer-facing checklist (titles plus NEG templates), cut at `limit` bytes."""
    try:
        data = merged_data(repo, ignore_repo_file=ignore_repo_file)
        out = ["## Domain checklist (generated by the harness from repo signals; not part of the signed packet)",
               "Treat each item as a review question: is there a NEG case and a test, or a justified waiver?"]
        seen = set()
        for name in domains or []:
            key = resolve_domain(name, data)
            out.append(f"### {key}")
            for item in checklist(key, data=data):
                if (item["id"], item["neg_raw"]) not in seen:
                    seen.add((item["id"], item["neg_raw"]))
                    out.append(f"- {item['id']}: {item['title']}. {item['neg']}")
        prompts = suggested_prompts(domains)[:8]
        out += ["### Follow-up questions"] + [f"- {p}" for p in prompts] if prompts else []
    except (ValueError, KeyError):
        return ""
    text = "\n".join(out) + "\n"
    raw = text.encode("utf-8")
    return text if len(raw) <= limit else raw[:limit].decode("utf-8", "ignore").rsplit("\n", 1)[0] + "\n- (checklist truncated)\n"


# --------------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    det = sub.add_parser("detect")
    det.add_argument("--repo", default=".")
    det.add_argument("--json", action="store_true")
    for name in ("checklist", "scaffold"):
        item = sub.add_parser(name)
        item.add_argument("--domain", required=True)
        item.add_argument("--repo", default=None, help="repo whose .harness/domain-gates.json adds items")
    args = parser.parse_args(argv)
    try:
        if args.command == "detect":
            found = detect(Path(args.repo))
            if args.json:
                print(json.dumps(found, indent=1))
            elif not found:
                print("no blockchain domain detected")
            for item in ([] if args.json else found):
                print(f"{item['domain']} ({item['confidence']}): " + "; ".join(item["evidence"]))
            return 0
        if args.command == "checklist":
            for item in checklist(args.domain, args.repo):
                print(f"- {item['id']}: {item['title']}\n    NEG: {item['neg']}\n    Verify by: {item['verify']}")
            return 0
        for item in scaffold(args.domain, args.repo):
            print(f"{item['id']}: {item['title']}")
            for command in item.get("commands", []):
                print(f"    $ {command}")
            if item.get("notes"):
                print(f"    note: {item['notes']}")
        return 0
    except (KeyError, ValueError) as error:
        print(f"domain-gates: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
