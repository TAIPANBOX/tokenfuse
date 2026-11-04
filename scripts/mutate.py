import json, pathlib, sys
mid = sys.argv[1]
m = next(x for x in json.load(open("scripts/mutants.json")) if x["id"] == mid)
p = pathlib.Path(m["file"])
s = p.read_text()
n = s.count(m["old"])
assert n == 1, f"{mid}: the text to mutate occurs {n} times in {m['file']}, want exactly 1"
p.write_text(s.replace(m["old"], m["new"], 1))
print(f"APPLIED {mid}: {m['why']}")
print(m["run"])
