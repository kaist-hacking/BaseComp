import os
import sys
import time
import shutil

import idc

from test_utils import get_binary, sandbox

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))

from analyses.cache import Cache

cache = Cache()

@cache.cache('cache')
def f():
    time.sleep(1)
    return int(time.time())

def test_binary():
    binary = get_binary('hello')
    assert os.path.samefile(binary, idc.get_input_file_path())

def test_simple():
    start1 = time.time()
    r1 = f()
    elapsed1 = time.time() - start1
    assert elapsed1 >= 1

    start2 = time.time()
    r2 = f()
    elapsed2 = time.time() - start2
    assert elapsed2 < 1
    assert r1 == r2

    shutil.rmtree(cache.root_dir)

@sandbox
def main():
    test_binary()
    test_simple()
    idc.qexit(0)

main()
