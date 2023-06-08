import os
import string
import re
import pickle

import idc
import ida_ua
import ida_segment
import ida_bytes
import ida_netnode
import ida_hexrays
import idaapi

STR_CHARS = string.ascii_letters + string.digits + '_ '
STR_CHARS = STR_CHARS.encode()
STR_COMMENT_CHARS = string.ascii_letters + string.punctuation + string.digits + ' \t\n'
STR_COMMENT_CHARS = STR_COMMENT_CHARS.encode()
FUNCNAME_CHARS = string.ascii_letters + '_' + string.digits
FUNCNAME_CHARS = FUNCNAME_CHARS.encode()


GLOBAL_VAR_LIST = ['FUNC_BY_LS', 'FUNC_BY_PTR', 'dbt_list']
#stores global variables for reopening IDA Pro
def store_globals(var_list=None):
    global GLOBAL_VAR_LIST
    if var_list is None:
        var_list = GLOBAL_VAR_LIST
    elif type(var_list) is not list:
        var_list = [var_list]
    #dump each global variable
    for varname in var_list:
        if varname in globals():
            var = globals()[varname]
            filename = get_root_filename()
            dumpname = "%s_%s.dmp"%(filename, varname)
            with open(dumpname, 'wb') as f:
                pickle.dump(var, f)
            print("%s saved to %s"%(varname, dumpname))
        else:
            print("%s not found in globals"%varname)

def load_globals(var_list=None):
    global GLOBAL_VAR_LIST
    if var_list is None:
        var_list = GLOBAL_VAR_LIST
    elif type(var_list) is not list:
        var_list = [var_list]
    #load each global variable
    for varname in var_list:
        filename = get_root_filename()
        dumpname = "%s_%s.dmp"%(filename, varname)
        if os.path.exists(dumpname):
            with open(dumpname, 'rb') as f:
                globals()[varname] = pickle.load(f)
                var = globals()[varname]
            print("%s loaded from %s"%(varname, dumpname))
        else:
            print("%s dump not found"%varname)

def create_string(ea, length=idc.BADADDR):
    s = get_string(ea, length)
    if s:
        idc.create_strlit(ea, ea+len(s))

    return s

# ida's get_strlit_contents filters 0x1d, 0x9, 0x6, etc.
def get_string(ea, length=idc.BADADDR):
    end_ea = ea + length
    ret = []

    while ea < end_ea:
        # break if current ea is already assigned
        if not idc.is_loaded(ea):
            break

        byte = ida_bytes.get_byte(ea)
        if byte == 0: #NULL terminate
            break

        ret.append(byte)
        ea += 1

    return bytes(ret)


def check_string(ea, length=idc.BADADDR):
    global STR_CHARS, STR_COMMENT_CHARS

    if isinstance(ea, int):
        s = get_string(ea, length)
    elif isinstance(ea, str):
        s = ea.encode()
    elif isinstance(ea, bytes):
        s = ea

    if not s:
        return False

    # strict limit
    if len(s) < 4:
        return False

#    # possible strings
#    if len(s) < 10:
#        if any(ch not in STR_CHARS for ch in s):
#            return False

    # highly likely comments

    if any(ch not in STR_COMMENT_CHARS for ch in s):
        return False

    return True


def check_funcname(data_ptr, length=30):
    global FUNCNAME_CHARS

    if isinstance(data_ptr, int):
        s = get_string(data_ptr)
    elif isinstance(data_ptr, str):
        s = data_ptr.encode()
    elif isinstance(data_ptr, bytes):
        s = data_ptr
    else:
        raise Exception

    if not s:
        return False

    if len(s) < 8:
        return False

    # function name would be less than 30 characters.
    if len(s) > length:
        return False

    #if s.upper() == s:
    #    return False

    if chr(s[0]) in string.digits:
        return False

    if any(ch not in FUNCNAME_CHARS for ch in s):
        return False

    # TODO: add other func name checks
    return True


# deprecated.
def set_funcname(ea, name):
    func_addr = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_addr == idc.BADADDR:
        return
    return set_entry_name(func_addr, name)


def set_entry_name(ea, name):
    cur_name = idc.get_name(ea)
    if cur_name.startswith(name):
        return cur_name

    name = check_name(name)
    status = idc.set_name(ea, name)
    if status:
        return name
    else:
        return


def is_name_exist(name):
    addr = idc.get_name_ea_simple(name)
    # if name already exists, we need to assign new name with suffix
    if addr != idc.BADADDR:
        return True
    else:
        return False


def check_name(orig_name):
    name = orig_name
    idx = 1
    while is_name_exist(name):
        name = "%s_%d" % (orig_name, idx)
        idx += 1

    return name


def create_entry(ea, bit_len, data_len):
    if bit_len == 8:
        flag = ida_bytes.byte_flag()
    elif bit_len == 16:
        flag = ida_bytes.word_flag()
    elif bit_len == 32:
        flag = ida_bytes.dword_flag()
    elif bit_len == 64:
        flag = ida_bytes.qword_flag()
    else:
        raise NotImplemented

    byte_len = bit_len // 8
    ida_bytes.create_data(ea, flag, byte_len * data_len, ida_netnode.BADNODE)


def make_type(bit_len, data_len):
    if bit_len == 8:
        return 'char[%d]' % (data_len)
    elif bit_len == 16:
        return 'short[%d]' % (data_len)
    elif bit_len == 32:
        return 'int[%d]' % (data_len)
    elif bit_len == 64:
        return 'long long[%d]' % (data_len)
    else:
        raise NotImplemented


def is_func_start(ea):
    if ea == idc.BADADDR:
        return False

    if idc.get_func_attr(ea, idc.FUNCATTR_START) != (ea & 0xfffffffe):
        return False

    return True


def is_assem(ea):
    # there may exist data section
    mnem = ida_ua.ua_mnem(ea)
    if not ida_ua.can_decode(ea) or not mnem:
        return False

    return True


def is_func(ea):
    if ea == idc.BADADDR:
        return False

    start_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)

    return start_ea <= ea < end_ea


def is_thumb(ea):
    return idc.get_sreg(ea, "T") == 1


def is_main(ea):
    seg = ida_segment.get_segm_by_name('MAIN')
    if not seg:
        seg = ida_segment.get_segm_by_name('ROM')
        if not seg:
            return False

    return seg.start_ea <= ea < seg.end_ea


def remove_function(ea=0x40CD659A):
    cnt = 0
    for xref in XrefsTo(ea):
        if xref.type != 0x11:
            continue
        call = xref.frm
        if ida_bytes.get_item_size(call) == 4:
            patch_dword(call, 0x00002000)
            cnt += 1
    print("%d removed"%cnt)

def add_decompiler_cmt(loc, comment):
    cfunc = idaapi.decompile(loc)
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[loc][0].ea
    tl = idaapi.treeloc_t()
    tl.ea = decompObjAddr
    commentSet = False
    for itp in range (idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()
    if not commentSet:
        print ("pseudo comment error at %08x" % loc)
    else:
        ida_bytes.set_cmt(loc, comment, True)


def get_model():
    if get_string(0x404BC9A0) == b'SrrcMain':
        return 'G977'
    if get_string(0x412D1C50) == b'Main':
        return 's6' #ramdump

def tprint(cexpr):
    if type(cexpr) == ida_hexrays.cinsn_t:
        # if insn
        cexpr = cexpr.cexpr
        if cexpr == None:
            print("None")
            return
    assert type(cexpr) == ida_hexrays.cexpr_t, type(cexpr)
    print(idaapi.tag_remove(cexpr.print1(None)))


def print_res():
    global funcs, times
    names = ['initial', 'scatterload', 'init_dbt',
             'linear_sweep', 'linear_sweep+ida',
             'pointer_analysis', 'init_functions',
             'init_strings',
             'dbt_func_analysis', 'dbt_xref_analysis', 'analyze_dbt',
             'check_message_dispatch']
    print('Procedure,# of Funcs,# of Main Funcs,Time')
    for idx in range(len(names)):
        func_num = len(funcs[idx])
        main_func_num = len(list(filter(lambda x: is_main(x), funcs[idx])))
        print('{},{},{},{:.3f}'.format(names[idx], func_num, main_func_num, times[idx]))