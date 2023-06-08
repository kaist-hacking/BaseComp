import utils

def symbolize_vendor(state, config):

    struct = state.solver.BVS('struct', 32)
    state.solver.add(struct == 0xfffe0000)
    state.memory.store(struct, state.solver.BVS('len', 16).reversed)
    state.regs.r1 = struct

    msg_buf = state.solver.BVS('message_buffer', 32)
    state.solver.register_variable(msg_buf, ("message_buffer",0x1))
    state.solver.add(msg_buf == 0xffff0000)
    state.memory.store(struct+4, msg_buf.reversed)

    sec_state = state.solver.BVS('security_state', 8)
    state.solver.register_variable(sec_state, ("security_state",0x1))
    state.solver.add(state.solver.Or(sec_state == 1, sec_state == 2))

def add_hook_vendor(proj, state, config):
    sec_state = list(state.solver.get_variables("security_state"))[0][1]
    proj.hook(config['get_state'], utils.create_hook(retval=sec_state))

def acceptable(state):
    return state.solver.eval(state.regs.r0) != 5