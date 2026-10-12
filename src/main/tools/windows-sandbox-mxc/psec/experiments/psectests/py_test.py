import os, sys, tempfile
print("TEST_TMPDIR=", os.environ.get("TEST_TMPDIR"), "TMPDIR=", os.environ.get("TMPDIR"), "TEMP=", os.environ.get("TEMP"))
from python.runfiles import runfiles  # rules_python runfiles library
r = runfiles.Create()
p = r.Rlocation("_main/psectests/data.txt")
print("rlocation:", p)
s = open(p).read().strip()
print("data:", repr(s))
assert s == "hello data"
d = tempfile.mkdtemp()
open(os.path.join(d, "f"), "w").write("x")
print("mkdtemp ok:", d)
print("PASS")
