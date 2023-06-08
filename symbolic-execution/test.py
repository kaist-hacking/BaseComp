import angr
import claripy
import logging
import monkeyhex
import datetime
import os
import time

from utils import rewind_call, is_constrained, is_related, debug, get_path
l = logging.getLogger('Analyzer')
l.setLevel(logging.DEBUG)

fake_ret = 0x1234

#avoid complicated crypto funcs
avoid = [
]

def hook_ret_sec_state(state):
    global sec_state
    l.debug('hook called 0x%x'%state.addr)
    rewind_call(state, retval=sec_state)

def hook_ret_0(state):
    #just return 0
    l.debug('hook called 0x%x'%state.addr)
    rewind_call(state, retval=0)

def hook_ret_1(state):
    #just return 0
    l.debug('hook called 0x%x'%state.addr)
    rewind_call(state, retval=1)

def filter_func(state):
    global avoid
    if state.addr == fake_ret:
        return 'found'
    elif (state.addr & 0xfffffffe) in avoid:
        l.debug('avoided 0x%x'%state.addr)
        return 'avoided'
    else:
        return 'active'

def until_found(simgr):
    if len(simgr.found) > 3:
        return True
    return False

def init(target, target_addr, hook_list, get_state):
    #target = '../firmwares/G977/modem.bin_2_MAIN_0x2260_0x40010000_0x2636680'
    # mediatek
    base_addr = 0
    arch = 'armel'
    options = {'main_opts' : {'backend':'blob', 'base_addr':base_addr, 'arch':arch}}

    proj = angr.Project(target, load_options=options)

    for addr in hook_list:
        proj.hook(addr, hook_ret_0)
    proj.hook(get_state, hook_ret_sec_state)

    # dual sim func?
    #context_select_addr = 0x40CD659A+1
    #proj.hook(context_select_addr, hook_ret_0)
    # log function
    #dm_log_addr = 0x4057B622+1
    #proj.hook(dm_log_addr, hook_ret_0)

    #check sec hdr
    #target_addr = 0x41437972+1
    #check sec compliance
    #target_addr = 0x41437E50+1
    state = proj.factory.blank_state(addr=target_addr, arch=arch)
    state.regs.lr = fake_ret

    return proj, state


def set_symbols(s):
    global sec_hdr, prot, sec_hdr2, prot2, sec_state, msg_types
    # initialize values of interest
    class_obj = s.solver.BVS('obj', 32)
    s.regs.r0 = class_obj

    # msg buf
    msg = s.solver.BVS('msg', 32)
    s.solver.add(msg == 0xfffe0000)
    s.memory.store(msg, s.solver.BVS('len', 16).reversed)
    s.regs.r1 = msg

    # payload
    payload = s.solver.BVS('ptr_payload', 32)
    s.solver.add(payload == 0xffff0000)
    s.memory.store(msg+4, payload.reversed)

    sec_hdr = s.solver.BVS('sec_hdr', 4)
    prot = s.solver.BVS('prot', 4)
    data = s.solver.Concat(sec_hdr, prot)
    s.memory.store(payload, data)
    sec_hdr2 = s.solver.BVS('sec_hdr2', 4)
    prot2 = s.solver.BVS('prot2', 4)
    data = s.solver.Concat(sec_hdr2, prot2)
    s.memory.store(payload+6, data)
    #s.solver.add(s.solver.And(sec_hdr != 1, sec_hdr != 2))

    sec_state = s.solver.BVS('sec_state', 8)
    #s.memory.store(state_addr, sec_state)
    s.solver.add(s.solver.Or(sec_state == 1, sec_state == 2))

    msg_type1 = s.solver.BVS('msg_type1', 8)
    s.memory.store(payload+1, msg_type1)
    msg_type2 = s.solver.BVS('msg_type2', 8)
    s.memory.store(payload+2, msg_type2)
    msg_type3 = s.solver.BVS('msg_type7', 8)
    s.memory.store(payload+7, msg_type3)
    msg_type4 = s.solver.BVS('msg_type8', 8)
    s.memory.store(payload+8, msg_type4)

    msg_types = [msg_type1, msg_type2, msg_type3, msg_type4]


def analyze_result(simgr):
    global sec_hdr, prot, sec_hdr2, prot2, sec_state, msg_types
    l.debug("Total {} states found".format(len(simgr.found)))
    curtime = datetime.datetime.now().strftime('%m%d-%H%M%S')
    #os.mkdir("results/{}".format(curtime))
    for idx, s in enumerate(simgr.found):
        ret_val = s.solver.eval(s.regs.r0)
        if ret_val == 5:
            #l.debug("{}: Check failed".format(idx))
            continue
        l.debug("{}: Check passed {}".format(idx, ret_val))
        with open("results/mediatek_{}.log".format(curtime, idx),'a+') as f:
            #eval sec_hdr
            f.write("\n {} ==============\n".format(idx))
            sec_hdrs = s.solver.eval_upto(sec_hdr, 10)
            constraints = s.solver.simplify()

            #log constraints
            for c in constraints:
                f.write(str(c)+'\n')

            l.debug("sec header values: {}".format(sec_hdrs))
            ss = s.solver.eval(sec_state)
            p = s.solver.eval(prot)
            l.debug("sec state: {}, prot: {}".format(ss, p))
            symbols = [sec_hdr2, prot2] + msg_types
            for bvs in msg_types:
                for c in constraints:
                    if is_related(c, bvs):
                        v = s.solver.eval(bvs)
                        l.debug("{}: {:x}".format(c, v))
            '''
            if len(sec_hdrs) == 1:
                if sec_hdrs[0] == 0:
                    if p == 2:
                        msg_type = s.solver.eval(msg_types[1])
                    else:
                        msg_type = s.solver.eval(msg_types[0])
                    l.debug("msg type: {:x}".format(msg_type))
                elif sec_hdrs[0] == 3:
                    msg_type = s.solver.eval(msg_types[2])
                    l.debug("msg type: {:x}".format(msg_type))
            '''


if __name__ == '__main__':
    
    st = time.time()

    target = "C:\\Users\\qqor\\K\\basecomp\\mediatek\\P25_flyme_pro7\\P25_flyme_pro7_md1rom.bin"
    #check sec compliance
    target_addr = 0x53B7E8+1
    avoid = [
        0x53B2DC, # integrity check CEmmSec::chkIntegrity
    ]
    hook_list = [
        0x142258+1, # something virtual sim? is_vsim_on
        0x2CFC0+1, # log dhl_trace
        0x4F8810+1, # malloc emm_get_ctrl_buff
        0x3FAB90 # memcpy __wrap_memcpy_from_thumb
    ]
    get_state = 0x4FFCB0 + 1 # CEmmIntState::getState
    proj, init_state = init(target, target_addr, hook_list, get_state)

    # 0x52C5C0, # replay check CEmmSecCtxtSmc::calDlNasCount
    #proj.hook(0x52C5C0, hook_ret_1)

    set_symbols(init_state)
    simgr = proj.factory.simgr(init_state)
    simgr.stashes['found'] = []
    simgr.stashes['avoided'] = []
    #simgr.run(filter_func = filter_func, until = until_found)
    simgr.run(filter_func = filter_func)

    analyze_result(simgr)

    en = time.time()
    l.info("Time consumed: {}".format(en-st))
