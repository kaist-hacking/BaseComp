import angr
import claripy
import sys
import time
from collections import defaultdict

def debug():
    import ipdb; ipdb.set_trace(sys._getframe().f_back)

time_dict = defaultdict(float)
count_dict = defaultdict(int)

def measure_time(f):
    def timed(*args, **kw):
        global time_dict
        ts = time.time()
        res = f(*args, **kw)
        te = time.time()
        time_dict[f.__qualname__] += te-ts
        count_dict[f.__qualname__] += 1
        return res
    return timed

page_size = 0x10000

def get_page(addr, page_size=page_size):
    #return 0
    return addr & ((0xffffffffffffffff*page_size) &0xffffffffffffffff)

def all2hex_helper(addr):
    if type(addr) is int:
        return hex(addr)
    elif type(addr) in (claripy.ast.bv.BV,):
        if not addr.symbolic:
            return hex(addr.args[0])
    elif type(addr) in [list, tuple]:
        return "[{}]".format(", ".join(map(all2hex_helper, addr)))

    return repr(addr)

class all2hex:
    def __init__(self, addr):
        self.addr = addr
    @measure_time
    def __str__(self):
        return all2hex_helper(self.addr)

def is_int(addr):
    return type(addr) is int

def is_sym(addr):
    return type(addr) in (claripy.ast.bv.BV,) and addr.symbolic


def show_time():
    global time_dict, count_dict
    for key in time_dict.keys():
        print("{} : {:.5f}s {}".format(key, time_dict[key], count_dict[key]))

def get_retval(state):
    cc = state.project.factory.cc()
    return state.regs.get(cc.return_val.reg_name)

def is_related(bv, addr):
    if type(bv) is claripy.ast.bv.BV:
        if bv.op == 'BVS':
            if len(bv.args) != len(addr.args):
                for a in addr.args:
                    return is_related(bv, a)
            return bv.args[0] == addr.args[0]
        elif bv.op == 'BVV':
            return False
    if hasattr(bv, 'args'):
        for v in bv.args:
            if is_related(v, addr):
                return True
    return False

def is_constrained(state, bv):
    for c in state.solver.simplify():
        if is_related(c, bv):
            return True
    return False

def diff_state(s1, s2):
    reg_diff = s1.registers.diff(s2.registers)[0]
    mem_diff = s1.memory.diff(s2.memory)

    return [reg_diff, mem_diff]

def get_string(state, addr, max_len=0x30):
    res = ''
    for i in range(max_len):
        byte = state.memory.load(addr+i,1)
        try:
            byte = state.solver.eval_one(byte)
        except:
            #symbolic string
            break
        if byte == 0:
            return res
        res+=chr(byte)
    return res

def get_path(state):
    path = [h.addr for h in state.history.lineage]
    if path[0] == None:
        path = path[1:]
    path.append(state.addr)
    return path

def rewind_call(state, name=None, retval=None):
    addr = state.solver.eval(state.regs.ip)
    if name is None:
        name = get_func_name(state, addr)
    if retval is None:
        retval = state.solver.BVS('ret_'+name, state.project.arch.bits)
    elif type(retval) is int:
        retval = state.solver.BVV(retval, state.project.arch.bits)

    if state.project.arch.name == 'AMD64':
        rewind_helper_x64(state, retval) # rewind stack
    elif state.project.arch.name == 'ARMEL':
        rewind_helper_arm(state, retval)
    elif state.project.arch.name == 'MIPS16e2':
        rewind_helper_mips(state, retval)
    else:
        raise NotImplementedError("unknown arch {}".format(p.project.arch.name))
    state.history.jumpkind = 'Ijk_FakeRet'

# helper functions for intra-procedural
def rewind_helper_x64(state, retval):
    ret = state.stack_pop()
    ret = state.solver.eval(ret)
    state.regs.rax = retval
    state.regs.ip = ret
    state.callstack.pop()

def rewind_helper_arm(state, retval):
    ret = state.regs.lr
    ret = state.solver.eval(ret)
    state.regs.r0 = retval
    state.regs.ip = ret
    state.callstack.pop() 

def rewind_helper_mips(state, retval):
    #ret = state.regs.ra
    ret = state.registers.load(132, 4)
    ret = state.solver.eval(ret)
    #state.regs.v0 = retval
    state.registers.store(16, retval, size=4)
    state.regs.ip = ret
    state.registers.store(136, ret, size=4)
    state.callstack.pop()

def get_func_name(state, addr):
    # currently, not retreive name from symbol
    return "sub_0x%x" % addr

def create_hook(retval):
    '''
    Creates a hook function returning the argument.
    
    :retval param:      Value of the hook to return.
    :returns:           Hook function.
    '''

    def hook(state):
        #print("reached hook {}, returns to {}".format(hex(state.addr), hex(state.solver.eval(state.regs.lr))))
        #print(state.callstack)
        rewind_call(state, retval=retval)
        pass

    return hook

class SkipUnconstrainedCalls(angr.ExplorationTechnique):
    def __init__(self):
        super().__init__()

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        for state in simgr.stashes['unconstrained']:
            try:
                rewind_call(state, retval=0)
                simgr.move(from_stash='unconstrained', to_stash='active', filter_func=(lambda x: x == state))
            except angr.errors.SimEmptyCallStackError:
                continue
            except:
                continue
        return 