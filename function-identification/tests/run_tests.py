#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess

TESTS = [
    ["call_distance_test.py", "call_distance"],
    ["cache_test.py", "hello"],
]

def parse_args():
    p = argparse.ArgumentParser()
    return p.parse_args()

if __name__ == '__main__':
    ida_home = os.environ.get("IDA_HOME")
    if ida_home is None:
        print("Please set IDA_HOME environment variable")
        sys.exit(1)

    idat = os.path.join(ida_home, "idat.exe")
    if not os.path.exists(idat):
        print(f"Cannot find idat.exe: {idat}")
        sys.exit(1)

    for script, binary in TESTS:
        script = os.path.abspath(script)
        binary = os.path.abspath(f'samples/{binary}')
        cmd = [idat, f"-S{script}", binary]
        subprocess.run(cmd, check=True)
