import idc
import idaapi
import idautils

import ida_ua
import ida_auto
import ida_offset
import ida_bytes
import ida_search
import ida_xref


import os
import time
import sys
sys.setrecursionlimit(10000)

from collections import defaultdict

from utils import get_string, create_string
from utils import check_funcname, set_funcname, check_string, add_decompiler_cmt
from utils import get_model
from slicer import SimpleBackwardSlicer
from analyze_data_struct import find_prev_func_cand
from analyze_data_struct import NONE, ARM, THUMB

class DebugTable(object):
    size = 28

    def __init__(self, dbt_addr):
        assert ida_bytes.get_bytes(dbt_addr, 4) == b"DBT:"
        self.magic = b"DBT:"
        self.addr = dbt_addr
        self.string_addr = ida_bytes.get_dword(dbt_addr+16)
        if self.string_addr != 0:
            self.string = get_string(self.string_addr)
        else:
            self.string = b''
        self.line = ida_bytes.get_dword(dbt_addr+20)
        self.path_addr = ida_bytes.get_dword(dbt_addr+24)
        self.path = get_string(self.path_addr)
        self.path_base = DebugTable.get_source_name(self.path)
        self.xrefs = set()
        self.args = []


    @staticmethod
    def get_source_name(path):
        if isinstance(path, bytes):
            pass
            #path = path.decode()
        base_name = os.path.basename(path)
        name, ext = os.path.splitext(base_name)

        # there may not exist other extensions. this is for verification.
        if ext in ['.c', '.cpp', '.h']:
            return name
        else:
            return None


    def set_ida(self):
        # TODO: create DBT struct in IDA
        dbt_addr = self.addr
        idc.del_items(dbt_addr, 0, 28)
        for i in range(0, 28, 4):
            ida_bytes.create_dword(dbt_addr+i, 4)

        # "DBT:"
        create_string(dbt_addr, 4)

        # string
        ida_offset.op_offset(dbt_addr+16, 0, idc.REF_OFF32)
        create_string(ida_bytes.get_dword(dbt_addr+16))

        # source file name
        ida_offset.op_offset(dbt_addr+24, 0, idc.REF_OFF32)
        create_string(ida_bytes.get_dword(dbt_addr+24))

        idc.set_name(dbt_addr, "DBT_%X" % (dbt_addr))


def init_dbt(ea=0, force=False):
    global dbt_list

    if not force and 'dbt_list' in globals() and len(dbt_list) > 0:
        print("%d DBT already found." % (len(dbt_list)))
        return

    dbt_list = dict()
    dbt_cnt = 0
    start_time = time.time()
    while ea != idc.BADADDR:
        dbt_addr = ida_search.find_binary(ea, idc.BADADDR, "3a544244", 16, idc.SEARCH_DOWN)
        if dbt_addr == idc.BADADDR:
            break

        # if we find new dbt, add it to the list
        if dbt_addr not in dbt_list:
            dbt = DebugTable(dbt_addr)
            dbt_list[dbt_addr] = dbt
            dbt_cnt += 1
            if dbt_cnt % 10000 == 0:
                print("0x%x: %d DBT has been found. (%0.3f secs)" % (dbt_addr, dbt_cnt, time.time() - start_time))

        else:
            dbt = dbt_list[dbt_addr]

        dbt.set_ida()

        ea = dbt_addr + DebugTable.size
        if not idc.is_mapped(ea):
            ea = next_inited(ea, idc.BADADDR)

    print("%d DBT has been found. (%0.3f secs)" % (len(dbt_list), time.time() - start_time))


def get_dbt_by_str(dbt_str):
    global dbt_list
    if 'dbt_list' not in globals() or len(dbt_list) == 0:
        init_dbt()

    target_dbt = None
    for dbt in dbt_list.values():
        if dbt_str in dbt.string.decode():
            target_dbt = dbt
            break

    return target_dbt


def get_dbt_xref_by_str(dbt_str):
    dbt = get_dbt_by_str(dbt_str)
    if dbt is None:
        return

    addr = None
    for xref in idautils.XrefsTo(dbt.addr):
        ea = xref.frm
        mnem = ida_ua.ua_mnem(ea)
        if ida_ua.can_decode(ea) and mnem:
            addr = ea
            break

    return addr


def create_func_by_dbt(ea):
    ea, mode = find_prev_func_cand(ea)
    if ea == idc.BADADDR:
        return False

    # set IDA segment register to specify ARM mode
    old_flag = idc.get_sreg(ea, "T")
    if mode == THUMB:
        idc.split_sreg_range(ea, "T", 1, idc.SR_user)
    elif mode == ARM:
        idc.split_sreg_range(ea, "T", 0, idc.SR_user)
    else:
        print("Unknown mode")
        raise NotImplemented

    # add_func ignores the existing function, but existing function is
    # already filtered when finding the candidate
    status = idc.add_func(ea)
    if status: 
        # Wait IDA's auto analysis
        ida_auto.auto_wait()

        return ea

    else:
        # IDA automatically make code, and this remains even though
        # add_func fails.
        ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND)

        # reset IDA segment register to previous ARM mode
        idc.split_sreg_range(ea, "T", old_flag, idc.SR_user)

        # Wait IDA's auto analysis
        ida_auto.auto_wait()

        return idc.BADADDR


# TODO: replace fetch_dbt_arg to slicer.fetch_arg_one
def fetch_dbt_arg(ea, reg_name, end_ea=idc.BADADDR, end_cnt=100):
    slicer = SimpleBackwardSlicer()
    values = slicer.find_reg_value(ea, reg_name, end_ea=end_ea, end_cnt=end_cnt)
    if not values:
        return idc.BADADDR

    return values.pop()


def fetch_log_dbt_func():
    # We assume that logging function should be called in numerous points.
    log_dbt_cands = []
    funcs = list(idautils.Functions())
    for ea in funcs:
        xrefs = list(idautils.CodeRefsTo(ea, 0))
        if len(xrefs) > len(funcs) * (2.0 / 3.0):
            log_dbt_cands.append((ea, len(xrefs)))

    assert len(log_dbt_cands) > 0
    log_dbt_cands.sort(key=lambda x: x[1], reverse=True)
    log_dbt_ea = log_dbt_cands[0][0]

    print('Found log_dbt function at 0x{:x}, {:d} candidates'.format(log_dbt_ea, len(log_dbt_cands)))

    wrappers = set()
    wrappers.add(log_dbt_ea)
    # There may exist wrappers of log_dbt function. Thus, we find them as well.
    for xref in idautils.XrefsTo(log_dbt_ea):
        if xref.type not in [idc.fl_JF, idc.fl_JN, idc.fl_F]:
            continue

        print('Found log_dbt wrapper at 0x{:x}'.format(xref.frm))
        wrappers.add(xref.frm)

    return wrappers


FUNC_BY_DBT = set()
FUNC_BY_DBT_TIME = None
XREFS_BY_DBT = set()
XREFS_BY_DBT_TIME = None
def analyze_dbt(end_cnt=0x100, find_func=True):
    global dbt_list
    global FUNC_BY_DBT, FUNC_BY_DBT_TIME
    global XREFS_BY_DBT, XREFS_BY_DBT_TIME

    if 'dbt_list' not in globals() or len(dbt_list) == 0:
        init_dbt()

    if 'FUNC_BY_DBT' not in globals() or len(FUNC_BY_DBT) == 0:
        FUNC_BY_DBT = set()

    if 'XREFS_BY_DBT' not in globals() or len(XREFS_BY_DBT) == 0:
        XREFS_BY_DBT = set()

    func_cnt = 0
    cand_cnt = 0

    if find_func:
        # There may exist functions that are not defined yet. We find those
        # functions using the xrefs of DBT, by checking function prologs.  This can
        # only find functions for code that is 1) disassembled and 2) not defined
        # as a function.
        # TODO: find functions from code that is not diassembled.
        print("Analyzing %d DBTs ..." % (len(dbt_list)))
        start_time = time.time()
        for idx, dbt_addr in enumerate(dbt_list.keys()):
            if idx % 10000 == 0:
                print('%d/%d' % (idx, len(dbt_list)))
            dbt = dbt_list[dbt_addr]
            dbt_str = dbt.string.decode()

            for xref in idautils.XrefsTo(dbt.addr):
                ea = xref.frm

                mnem = ida_ua.ua_mnem(ea)
                if not ida_ua.can_decode(ea) or not mnem:
                    continue

                # We only handle "MOV? R0, DBT" or "LDR? R0, DBT"
                # TODO: handle MOVW, MOVT.W
                if not any(mnem.startswith(word) for word in ['MOV', 'LDR']):
                    continue
                if idc.print_operand(ea, 0) != 'R0':
                    continue

                # Add current function if it is not defined yet.
                func_addr = idc.get_func_attr(ea, idc.FUNCATTR_START)
                if func_addr == idc.BADADDR:
                    func_addr = create_func_by_dbt(ea)
                    if func_addr == idc.BADADDR:
                        #print(" ==== create function by DBT failed")
                        #print('%x => %x: %s, %s' % (ea, dbt.addr, mnem, dbt_str))
                        continue

                    FUNC_BY_DBT.add(func_addr)

        FUNC_BY_DBT_TIME = time.time() - start_time
        print ("Found %d functions by DBT. (%0.3f secs)" % (len(FUNC_BY_DBT), FUNC_BY_DBT_TIME))

    # Now, we analyze each xref of log_dbt function as each DBT is not directly
    # used. In other words, some DBTs are referred using a relative address.
    # Thus, we slice backward and compute the actual address of each DBT xref,
    # and set the xref link.
    log_dbt_eas = fetch_log_dbt_func()
    for log_dbt_ea in log_dbt_eas:
        log_dbt_xrefs = list(idautils.CodeRefsTo(log_dbt_ea, 0))
        print("Analyzing {:d} xrefs to log_dbt at 0x{:x} ...".format(len(log_dbt_xrefs), log_dbt_ea))
        start_time = time.time()
        for idx, xref_ea in enumerate(log_dbt_xrefs):
            if idx % 10000 == 0:
                print('%d/%d' % (idx, len(log_dbt_xrefs)))

            # By parsing the log function, we get the real dbt.  We add this
            # because some offsets are arithmetically calculated.
            real_dbt_addr = fetch_dbt_arg(xref_ea, 'R0', end_cnt=end_cnt)
            if real_dbt_addr == idc.BADADDR or real_dbt_addr not in dbt_list:
                continue

            real_dbt = dbt_list[real_dbt_addr]
            real_dbt_str = real_dbt.string.decode()
            # Add new data offset xref edge for later manual IDA analysis
            idc.add_dref(xref_ea, real_dbt_addr, ida_xref.dr_O)
            ida_auto.auto_wait()
            XREFS_BY_DBT.add((xref_ea, real_dbt_addr))

    XREFS_BY_DBT_TIME = time.time() - start_time
    print ("Found %d DBT xrefs. (%0.3f secs)" % (len(XREFS_BY_DBT), XREFS_BY_DBT_TIME))
    set_dbt_comment()


def set_dbt_comment():
    # Add comments in decompiled code
    if 'XREFS_BY_DBT' not in globals() or len(XREFS_BY_DBT) == 0:
        return
    for xref_ea, dbt_addr in XREFS_BY_DBT:
        if dbt_addr not in dbt_list:
            continue
        dbt = dbt_list[dbt_addr]
        if dbt.string:
            try:
                add_decompiler_cmt(xref_ea, dbt.string.decode())
            except:
                continue


def get_obj_ea(e):
    #TODO: move somewhere like utils
    if e is None:
        return None

    # strip type casting / dereference / etc
    if e.opname == "num":
        return e.numval()
    elif e.opname == "obj":
        return e.obj_ea
    elif e.opname in ["cast", "ref", "ptr"]:
        return get_obj_ea(e.x)
    elif e.opname in ["add"]:
        # ex) *(&loc_424F1A84 + 1) = 6;
        # TODO: check other cases such as "sub", ...
        return sum(map(lambda x: get_obj_ea(x), e.operands.values()))
    elif e.opname == "call":
        # ex) LOWORD(dword_424F4544) = 1025;
        assert e.a.size() == 1
        return get_obj_ea(e.a[0])
    elif e.opname == "memref":
        return get_obj_ea(e.x) + e.m
    elif e.opname == "idx":
        return get_obj_ea(e.x) + (e.y.numval() * e.type.get_size())
    else:
        # TODO: check other cases
        # idx, var
        return get_obj_ea(e.x)


class DBTParser(idaapi.ctree_visitor_t):
    def __init__(self, ea, main, dbt_log_eas):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.func_name = idc.get_func_name(ea)
        self.cfunc = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)
        if self.cfunc is None:
            raise RuntimeError('decompile fail')
        self.ea = ea
        self.main = main # "main" ptr addr
        self.dbt_log_eas = dbt_log_eas # list of dbt_log func addr
        self.result = None
        return

    def run(self):
        self.apply_to(self.cfunc.body, None)
        return self.result

    def _parse_state(self, e):
        if self.result:
            # already found
            return
        args = e.a # carglist_t
        if(len(args)<5):
            return
        main = get_obj_ea(args[1])
        if main != self.main:
            return
        name_addr = get_obj_ea(args[4])
        if name_addr and check_funcname(name_addr, 70):
            self.result = get_string(name_addr).decode()
        return

    # This traverse all expressions (cexpr)
    def visit_expr(self, e):
        # find all candidates of dbt_log
        # dbt_log(..., off_41816F10, ..., ..., # func_name, 0xFECDBA98)
        op = e.op
        if op == idaapi.cot_call:
            if e.x.opname == 'obj':
                if e.x.operands['obj_ea'] in self.dbt_log_eas:
                    # found call dbt_log
                    self._parse_state(e)
        return 0