"""Require exactly the pinned Rust fixtures and success totals for each build step."""

import re
import sys
from collections import Counter
from pathlib import Path


APP_SERVER = "suite::v2::turn_start::turn_start_emits_raw_response_completed_with_upstream_usage"
SCHEMA_WRITER = "schema_fixtures_tests::write_schema_fixtures_from_env"
CASES = {
    "tracker": (
        "sse::responses::tests::response_model_observation_requires_bound_unambiguous_provider_metadata",
        "sse::responses::tests::response_model_observation_is_consumed_by_its_terminal_event",
    ),
    "sse": ("responses_sse_binds_http_model_header_to_its_one_response",),
    "websocket": ("suite::client_websockets::responses_websocket_model_observation_does_not_cross_response_boundaries",),
    "compaction": ("compact_remote_v2::tests::collect_compaction_output_accepts_additional_output_items",),
    "app-server": tuple(f"{APP_SERVER}::{case}" for case in (
        "without_usage_metadata", "without_amount", "null_amount", "zero_amount",
        "exact_amount", "null_extra", "zero_extra", "nested_extra",
    )),
    "schema-export-0": (SCHEMA_WRITER,),
    "schema-export-1": (SCHEMA_WRITER,),
    "schema-verify": tuple(f"schema_fixtures_tests::{case}" for case in (
        "typescript_schema_fixtures_match_generated",
        "json_schema_fixtures_match_generated",
        "stable_precomputed_exports_match_schema_fixtures",
        "experimental_precomputed_exports_match_generated",
    )),
}


def verify(label, output):
    expected = CASES[label]
    passed = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", output, re.MULTILINE)
    summaries = re.findall(r"^test result: ok\. ([0-9]+) passed; ([0-9]+) failed;", output, re.MULTILINE)
    if Counter(passed) != Counter(expected) or summaries != [(str(len(expected)), "0")]:
        raise ValueError(f"Focused fixture names or totals differ for {label}")
    return len(expected)


if __name__ == "__main__":
    label, log = sys.argv[1:]
    total = verify(label, Path(log).read_text())
    print(f"Verified {label}: {total} required fixtures passed")
