"""Regenerate canonical-JSON goldens from CPython: python3 -I gen_golden.py > golden.json (deterministic, seed 20261104)."""
import json, random, struct, sys
rng = random.Random(20261104)
strings = ["", "plain", 'q"uo\\te', "\n\r\t\b\f\x00\x01\x1f\x7f", "<>&'", "café", "nb sp", "  ",
           "日本", "\U0001F600 astral", "﻿bom", "\udbff"[:0] + "\U0010FFFF"]
for _ in range(40):
    strings.append("".join(chr(rng.choice([rng.randrange(0x20, 0x7f), rng.randrange(0, 0x20), rng.randrange(0x80, 0xd800),
                                         rng.randrange(0xe000, 0x110000)])) for _ in range(rng.randrange(1, 12))))
floats = [0.0, -0.0, 1.0, -1.5, 0.1, 1e16, 1e15, 123456789012345678.0, 1e-4, 1e-5, 1.5e-7, 5e-324, 1.7976931348623157e308,
          2.0**53, 1/3, 100.0, 12345.678]
for _ in range(200):
    floats.append(struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0])
floats = [f for f in floats if f == f and f not in (float("inf"), float("-inf"))]
structs = [{"b": 1, "a": [True, False, None], "é": "x", "A": {"z": -7, "y": 18446744073709551615}},
           [], {}, [{"k": "v"}, [[]]], {"sha": "abc", "files": ["x.py", "y.py"], "n": 0}]
out = {"strings": [[s, json.dumps(s, ensure_ascii=True)] for s in strings],
       "floats": [[f.hex(), json.dumps(f)] for f in floats],
       "structs": [[json.dumps(v, ensure_ascii=False), json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)] for v in structs]}
json.dump(out, sys.stdout, ensure_ascii=True, indent=0)
