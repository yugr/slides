#!/usr/bin/env python3

# Simple script which checks if program is protected from StackClash attacks.

import os.path
import re
import subprocess
import sys
import time


me = os.path.basename(__file__)


def error(msg):
    """
    Print nicely-formatted error message and exit.
    """
    sys.stderr.write(f"{me}: error: {msg}\n")
    sys.exit(1)


def run(cmd, fatal=True, tee=False, **kwargs):
    """
    Simple wrapper for subprocess.
    """
    if isinstance(cmd, str):
        cmd = cmd.split(" ")
    #  print(cmd)
    t1 = time.perf_counter_ns()
    p = subprocess.run(
        cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )
    t2 = time.perf_counter_ns()
    out = p.stdout.decode()
    err = p.stderr.decode()
    if fatal and p.returncode != 0:
        cmds = " ".join(cmd)
        error(f"'{cmds}' failed:\n{out}{err}")
    if tee:
        sys.stdout.write(out)
        sys.stderr.write(err)
    return p.returncode, out, err, (t2 - t1) / 1e9


_, out, err, _ = run(['objdump', '-d', sys.argv[1]])

has_large_stack_allocs = False
for line in out.splitlines():
    m = re.search(r'sub\s+\$?(0x[0-9a-f]+),\s*%rsp', line)
    if m is not None:
        size = int(m[1], 16)
        # Do not fire on disguised additions e.g.
        # sub    $0xffffffffffffff80,%rsp
        if 4096 <= size < 0x7fffffff:
            has_large_stack_allocs = True
    m = re.search(r'orq\s+\$?0x0\s*,\s*(0x[0-9a-f]+)?\(%rsp\)', line)
    if m is not None:
        sys.exit(0)

sys.exit(1 if has_large_stack_allocs else 0)
