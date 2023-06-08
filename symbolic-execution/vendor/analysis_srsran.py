import utils

def symbolize_vendor(state, config):

    pdu = state.solver.BVS("pdu", 0x410*8)
    state.solver.add(pdu == 0xffffcccc00000000)
    msg_buf = pdu + 0x400
    state.solver.register_variable(pdu, ("pdu", 0x1))
    state.solver.register_variable(msg_buf, ("message_buffer",0x1))
    
    sec_state = state.solver.BVS('security_state', 8)
    state.solver.register_variable(sec_state, ("security_state",0x1))
    state.solver.add(state.solver.Or(sec_state == 1, sec_state == 2))

def add_hook_vendor(proj, state, config):
    pdu = list(state.solver.get_variables("pdu"))[0][1]
    proj.hook(config['get_pdu'], utils.create_hook(retval=pdu))

def acceptable(state):
    return True