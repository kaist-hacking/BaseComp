import utils

def symbolize_vendor(state, config):

    struct = state.solver.BVS('struct', 32)
    state.solver.add(struct == 0xfffe0000)
    len = state.solver.BVS('len', 16)
    state.solver.register_variable(len, ("len",0x1))
    state.memory.store(struct, len.reversed)
    state.registers.store(28, struct, size=4) # regs.a1

    msg_buf = state.solver.BVS('message_buffer', 32)
    state.solver.register_variable(msg_buf, ("message_buffer",0x1))
    state.solver.add(msg_buf == 0xffff0000)
    state.memory.store(struct+4, msg_buf.reversed)

    sec_state = state.solver.BVS('security_state', 32)
    state.solver.register_variable(sec_state, ("security_state",0x1))
    state.solver.add(state.solver.Or(sec_state == 1, sec_state == 2))

def add_hook_vendor(proj, state, config):
    sec_state = list(state.solver.get_variables("security_state"))[0][1]
    proj.hook(config['get_state'], utils.create_hook(retval=sec_state))

def acceptable(state):
    # 16 is the offset for v0
    if state.solver.eval(state.registers.load(16,4)) == 1:
        len = list(state.solver.get_variables("len"))[0][1]
        if state.solver.max(len) < 3:
            return False
        return True
    else:
        return False