"""Fixed native GoodQA browser-client launcher; no MCP or authority implementation."""
import os
import stat
import sys

HELPER = "/Applications/goodqa.app/Contents/Resources/agent/goodqa-agentd"


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        sys.stderr.write("goodqa-local-browser: no arguments are supported\n")
        return 64
    try:
        mode = os.lstat(HELPER).st_mode
        if not stat.S_ISREG(mode) or not mode & 0o111:
            return unavailable()
        os.execv(HELPER, [HELPER, "browser-client", "mcp-stdio"])
    except OSError:
        pass
    # exec never returns on success. Do not turn a failed handoff into success.
    return unavailable()


def unavailable():
    sys.stderr.write("goodqa-local-browser: native browser client unavailable\n")
    return 69


if __name__ == "__main__":
    sys.exit(main())
