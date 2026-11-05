#!/usr/bin/env python3
"""The one model-tier table and its pure lookups (GoodQA goodqa#14527).

Rungs: R0 Sonnet/Terra, R1..R3 Opus/Sol at medium/high/xhigh (writing), R4 Opus/Sol max (review only),
R5 Fable/Astra medium (writing, user permission), R6 Fable/Astra high (review only, user permission).
The Claude and OpenAI model on a rung are interchangeable. Every lookup is a pure function of the table
and its arguments; unknown inputs return None (callers reset to the lowest rung and record why).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re


class TierError(ValueError):
    """The tier table is missing, malformed or names something it does not define."""


DEFAULT_PATH = Path(__file__).resolve().parent / 'model_tiers.json'
MAX_BYTES = 65536
_EFFORTS = ('low', 'medium', 'high', 'xhigh', 'max')
_RUNG = re.compile(r'^R\d{1,2}$')
_PREFIXES = ('us.anthropic.', 'eu.anthropic.', 'anthropic.', 'global.anthropic.')


def load_policy(path=None):
    """Load and validate the table. Any defect raises TierError so callers fail closed."""
    path = Path(path or os.environ.get('AGENT_HARNESS_TIER_POLICY') or DEFAULT_PATH)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise TierError('tier table unreadable: %s' % type(error).__name__) from None
    if len(raw) > MAX_BYTES:
        raise TierError('tier table oversized')
    try:
        policy = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise TierError('tier table is not valid JSON') from None
    validate(policy)
    return policy


def validate(policy):
    if not isinstance(policy, dict) or policy.get('schema') != 1:
        raise TierError('tier table schema must be 1')
    if policy.get('mode') not in ('warn', 'enforce'):
        raise TierError('tier table mode must be warn or enforce')
    rungs = policy.get('rungs')
    if not isinstance(rungs, dict) or not rungs:
        raise TierError('tier table has no rungs')
    for name, rung in rungs.items():
        if not _RUNG.fullmatch(name) or not isinstance(rung, dict):
            raise TierError('bad rung %r' % (name,))
        for key in ('effort', 'writable', 'reviewer_rung', 'needs_user_permission', 'ultracode', 'models'):
            if key not in rung:
                raise TierError('rung %s lacks %s' % (name, key))
        if rung['effort'] not in _EFFORTS:
            raise TierError('rung %s has an unknown effort' % name)
        for flag in ('writable', 'needs_user_permission', 'ultracode'):
            if type(rung[flag]) is not bool:
                raise TierError('rung %s %s must be a bool' % (name, flag))
        if rung['reviewer_rung'] is not None and rung['reviewer_rung'] not in rungs:
            raise TierError('rung %s names an undefined reviewer rung' % name)
        if not isinstance(rung['models'], dict) or set(rung['models']) != {'claude', 'openai'}:
            raise TierError('rung %s must name a claude and an openai model' % name)
    for key in ('lowest_rung', 'top_writing_rung', 'unknown_author_reviewer_rung'):
        if policy.get(key) not in rungs:
            raise TierError('%s is not a defined rung' % key)
    if type(policy.get('failures_per_rung')) is not int or policy['failures_per_rung'] < 1:
        raise TierError('failures_per_rung must be a positive integer')
    limits = policy.get('ladder_limits')
    if (not isinstance(limits, dict) or type(limits.get('max_review_launches')) is not int
            or type(limits.get('max_rung_climbs')) is not int
            or type(limits.get('max_total_review_usd')) not in (int, float)):
        raise TierError('ladder_limits are malformed')
    families = policy.get('families')
    if not isinstance(families, dict) or set(families) != {'claude', 'openai'}:
        raise TierError('families must cover claude and openai')
    for harness, table in families.items():
        for family, spec in table.items():
            if not isinstance(spec, dict) or not isinstance(spec.get('rung_by_effort'), dict):
                raise TierError('family %s/%s is malformed' % (harness, family))
            for effort, rung in spec['rung_by_effort'].items():
                if effort != '*' and effort not in _EFFORTS or rung not in rungs:
                    raise TierError('family %s/%s maps to an undefined rung' % (harness, family))
            try:
                re.compile(spec.get('id_pattern', '$^'))
            except re.error:
                raise TierError('family %s/%s has a bad id pattern' % (harness, family)) from None
    if not policy['rungs'][policy['lowest_rung']]['writable']:
        raise TierError('the lowest rung must be writable')


def rung_order(policy):
    """Rung names sorted by number: the ladder order."""
    return sorted(policy['rungs'], key=lambda name: int(name[1:]))


def rung_index(policy, rung):
    order = rung_order(policy)
    if rung not in order:
        raise TierError('undefined rung %r' % (rung,))
    return order.index(rung)


def writing_rungs(policy):
    return [name for name in rung_order(policy) if policy['rungs'][name]['writable']]


def next_writing_rung(policy, rung):
    """The next writable rung above `rung`, or None at the top of the writing ladder."""
    order = writing_rungs(policy)
    if rung not in order:
        raise TierError('rung %r is not a writing rung' % (rung,))
    position = order.index(rung)
    return order[position + 1] if position + 1 < len(order) else None


def normalize_effort(value, policy):
    if value is None:
        return policy.get('default_effort', 'medium')
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text == 'ultracode':
        text = 'xhigh'  # the CLI maps --effort ultracode to xhigh
    return text if text in _EFFORTS else None


def normalize_model(value):
    """Strip provider prefixes and context suffixes; lower-case. Unknown types return None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for prefix in _PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = re.sub(r'\[\d+[kKmM]?\]$', '', text)
    text = re.sub(r'@\d{8}$', '', text)
    return text.lower()


def classify(model, effort, policy):
    """(rung, harness, family, effort) for an observed model and effort, or None when not on the table."""
    name = normalize_model(model)
    level = normalize_effort(effort, policy)
    if name is None or level is None:
        return None
    for harness, table in policy['families'].items():
        for family, spec in table.items():
            if name in [alias.lower() for alias in spec.get('aliases', [])] or re.search(spec.get('id_pattern', '$^'), name):
                mapping = spec['rung_by_effort']
                rung = mapping.get(level, mapping.get('*'))
                if rung is None:
                    return None
                return {'rung': rung, 'harness': harness, 'family': family, 'effort': level}
    return None


def spawn_spec(policy, rung, harness='claude'):
    """What to launch for a rung on a harness: model, effort and the rung's flags."""
    if rung not in policy['rungs']:
        raise TierError('undefined rung %r' % (rung,))
    if harness not in ('claude', 'openai'):
        raise TierError('unknown harness %r' % (harness,))
    entry = policy['rungs'][rung]
    return {'rung': rung, 'harness': harness, 'model': entry['models'][harness], 'effort': entry['effort'],
            'writable': entry['writable'], 'needs_user_permission': entry['needs_user_permission'],
            'ultracode': entry['ultracode'], 'review_budget_usd': entry.get('review_budget_usd'),
            'timeout_minutes': entry.get('timeout_minutes')}


def reviewer_for(policy, author_rung, author_harness='unknown', available=None):
    """Deterministic reviewer selection: one rung above the author, other harness preferred.

    `available` maps harness -> bool (executable present, auth not revoked, pool not down). When the
    preferred harness is unavailable the same harness one effort up is used, as the ladder rule says.
    An unknown author gets the configured unknown-author reviewer rung and the result is flagged.
    """
    available = {'claude': True, 'openai': True, **(available or {})}
    author_unknown = author_rung is None or author_rung not in policy['rungs']
    if author_unknown:
        rung = policy['unknown_author_reviewer_rung']
        why = 'author unknown: lowest writer rung reviewer (user decision Q1)'
    else:
        rung = policy['rungs'][author_rung]['reviewer_rung']
        why = 'one rung above the author'
        if rung is None:
            return {'rung': None, 'harness': None, 'model': None, 'effort': None, 'author_unknown': False,
                    'cross_harness': False, 'why': 'review-only rung needs no reviewer (user decision Q2)'}
    preferred = policy['preferred_review_harness'].get(author_harness, 'openai')
    other = 'claude' if preferred == 'openai' else 'openai'
    if available.get(preferred):
        chosen, cross, note = preferred, preferred != author_harness, 'cross-harness preferred'
    elif available.get(other):
        chosen, cross = other, other != author_harness
        # Same harness as the author: one effort up when the table has a higher rung on this harness.
        above = next_rung_above(policy, rung)
        if above is not None and author_harness == other:
            rung, note = above, 'preferred harness unavailable: same harness one effort up'
        else:
            note = 'preferred harness unavailable: same harness at the reviewer rung'
    else:
        return {'rung': rung, 'harness': None, 'model': None, 'effort': policy['rungs'][rung]['effort'],
                'author_unknown': author_unknown, 'cross_harness': False, 'why': 'no review harness available'}
    spec = spawn_spec(policy, rung, chosen)
    return {**spec, 'author_unknown': author_unknown, 'cross_harness': cross, 'why': why + '; ' + note}


def next_rung_above(policy, rung):
    order = rung_order(policy)
    position = order.index(rung)
    return order[position + 1] if position + 1 < len(order) else None


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    show = sub.add_parser('classify'); show.add_argument('--model', required=True); show.add_argument('--effort')
    spawn = sub.add_parser('spawn'); spawn.add_argument('--rung', required=True); spawn.add_argument('--harness', default='claude')
    review = sub.add_parser('reviewer'); review.add_argument('--author-rung'); review.add_argument('--author-harness', default='unknown')
    review.add_argument('--unavailable', action='append', default=[], choices=('claude', 'openai'))
    sub.add_parser('table')
    args = parser.parse_args(argv)
    policy = load_policy(args.policy)
    if args.action == 'classify':
        value = classify(args.model, args.effort, policy)
    elif args.action == 'spawn':
        value = spawn_spec(policy, args.rung, args.harness)
    elif args.action == 'reviewer':
        value = reviewer_for(policy, args.author_rung, args.author_harness,
                             {name: False for name in args.unavailable})
    else:
        value = {name: spawn_spec(policy, name, 'claude') | {'openai_model': policy['rungs'][name]['models']['openai']}
                 for name in rung_order(policy)}
    print(json.dumps(value, sort_keys=True, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
