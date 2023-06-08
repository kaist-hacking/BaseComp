import utils

def symbolize_vendor(state, config):

    msg_buf = state.solver.BVS('message_buffer', 32)
    state.solver.register_variable(msg_buf, ("message_buffer",0x1))
    state.regs.r0 = msg_buf
    state.solver.add(state.regs.r0 == 0xffff0000)

    sec_state = state.solver.BVS('security_state', 8)
    state.solver.register_variable(sec_state, ("security_state",0x1))
    state.memory.store(config['sec_state'], sec_state)
    state.solver.add(state.solver.Or(sec_state == 1, sec_state == 2))

def add_hook_vendor(proj, state, config):
    proj.hook(config['replay_func'], utils.create_hook(retval=1))
    
def acceptable(state):
    return state.solver.eval(state.regs.r0) != 0