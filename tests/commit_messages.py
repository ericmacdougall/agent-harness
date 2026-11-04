"""Policy-compliant commit messages for test fixtures (see harness/hooks/commit_policy.json)."""


def message(summary: str, kind: str = "chore", scope: str = "fixture", refs: str = "none (test fixture commit)") -> str:
    """Return a unique compliant message; the summary must be an imperative phrase."""
    return (f"{kind}({scope}): {summary}\n\n"
            f"Why: the test needs a commit that records {summary}.\n"
            f"What: {summary} inside the disposable fixture repository.\n"
            "Testing: not run: fixture commit inside a unit test\n"
            f"Refs: {refs}\n")
