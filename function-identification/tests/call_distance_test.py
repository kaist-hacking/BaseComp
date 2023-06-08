import os

import idc
import idaapi

from test_utils import get_binary, sandbox
from call_distance import CallDistance

def test_binary():
    binary = get_binary('call_distance')
    assert(os.path.samefile(binary, idc.get_input_file_path()))

def test_simple():
    cd = CallDistance()
    foo = cd.fea_to_idx(idaapi.get_name_ea(idaapi.BADADDR, "foo"))
    bar = cd.fea_to_idx(idaapi.get_name_ea(idaapi.BADADDR, "bar"))
    baz = cd.fea_to_idx(idaapi.get_name_ea(idaapi.BADADDR, "baz"))
    assert cd.is_caller(foo, bar)
    assert cd.is_caller(foo, baz)
    assert cd.is_caller(bar, baz)

    assert cd.is_caller(foo, bar, limit=1)
    assert cd.is_caller(bar, baz, limit=1)
    assert not cd.is_caller(foo, baz, limit=1)
    assert cd.is_caller(foo, baz, limit=2)

@sandbox
def main():
    test_binary()
    test_simple()
    idc.qexit(0)

main()
