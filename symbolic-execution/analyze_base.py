import angr
import logging
import datetime
import os
import yaml
import argparse
import time
import importlib.util
import sys

from utils import is_related, create_hook, SkipUnconstrainedCalls

# Support MIPS16e2
from arch_mips16e2 import ArchMIPS16e2
from pyvex.lifting import register, LibVEXLifter
from angr.calling_conventions import register_default_cc, SimCCO32
register(LibVEXLifter, 'MIPS16e2')
register_default_cc("MIPS16e2", SimCCO32)

l = logging.getLogger('Analyzer')
l.setLevel(logging.WARNING)

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--firmconf", help="Path to firmware config file.", default='config_firmware.yaml')
parser.add_argument("-v", "--vendorconf", help="Path to vendor config file.", default='config_vendor.yaml')
parser.add_argument("-fn", "--firmname", required=True, help="Firmware name in config file.")
args = parser.parse_args()

POSSIBLE_MSG_TYPES = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4E, 0x50, 0x51, 0x52, 0x53, 0x54, 0x5C, 0x55, 0x56, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x68, 0x69, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD9, 0xDA, 0xDB, 0xE8, 0x0F, 0x00, 0x19]
NUM_OF_POSSIBLE_MSG_TYPES = len(POSSIBLE_MSG_TYPES)

FAKE_RETURN_ADDR = 0x1234

def create_filter_func(config):
    '''
    Creates a filter function based on the input configuration.

    :config param:      Configuration of target firmware.
    :returns:           Filter function.
    '''
    
    def filter_func(state):
        if state.thumb:
            cur_addr = state.addr-1
        else:
            cur_addr = state.addr
        
        if cur_addr == config['dest_addr']:
            return 'found'
        elif cur_addr == FAKE_RETURN_ADDR:
            return 'found'
        elif cur_addr == config['mac_validation_func']:
            return 'avoided'
        else:
            return 'active'

    return filter_func

def get_config(firm_conf, vendor_conf, firmname):
    '''
    :fn param:      Name of the yaml file.
    :firm param:    Target firmware name.
    :returns:       Configuration of target firmware.
    '''
    with open(firm_conf, 'r') as f:
        conf_f_all = yaml.safe_load(f)
    conf_f = conf_f_all[firmname]

    with open(vendor_conf, 'r') as f:
        conf_v_all = yaml.safe_load(f)

    conf_v = conf_v_all[conf_f['vendor']]

    config = {
        'analysis': conf_v['analysis'],
        'arch': conf_v['arch'],
        'base_addr': conf_v['base_addr'],
        'unconstrained': conf_v['unconstrained'],
        'sec_state_secure_value': conf_v['sec_state_secure_value'],
        'sec_state_insecure_value': conf_v['sec_state_insecure_value'],

        'target': conf_f['target'],
        'dest_addr': conf_f['dest_addr'],
        'integrity_func': conf_f['integrity_func'],
        'mac_validation_func': conf_f['mac_validation_func'],
        'skip_funcs': conf_f['skip_funcs'],
    }

    for arg in conf_v['additional']:
        config[arg] = conf_f[arg]

    return config

def import_analysis(analysis_path):
    '''
    :analysis_path param:   Path to vendor specific analysis file.
    :returns:               Module of analysis file.
    '''
    spec = importlib.util.spec_from_file_location("vs_analysis", analysis_path)
    md = importlib.util.module_from_spec(spec)
    sys.modules["vs_analysis"] = md
    spec.loader.exec_module(md)

    return md

def init(config):
    '''
    :param config:      Config file of firmware.
    :returns:           Project and state instance.
    '''
    if config['arch'] == 'mips16e2':
        options = {'main_opts' : {'backend':'blob', 'base_addr':config['base_addr']}}
        proj = angr.Project(config['target'], arch=ArchMIPS16e2(), load_options=options)
    else:
        options = {'main_opts' : {'backend':'blob', 'base_addr':config['base_addr'], 'arch':config['arch']}}
        proj = angr.Project(config['target'], load_options=options)

    for addr in config['skip_funcs']:
        proj.hook(addr, create_hook(retval=0))

    state = proj.factory.blank_state(addr=config['integrity_func'])
    
    if config['arch'] == 'arm':
        state.regs.lr = FAKE_RETURN_ADDR
    elif config['arch'] == 'amd64':
        #TODO: set return value
        pass
    elif config['arch'] == 'mips16e2':
        # 132 is the offset for register ra
        state.registers.store(132, FAKE_RETURN_ADDR, size=4)

    return proj, state

def symbolize(state, config, module):
    '''
    :param state:       State of project.
    :param config:      Config file of firmware.
    :param module:      Module of analysis file.
    :returns:           Symbolic variables.
    '''

    def create_msg_type_cond(var):
        cond = False
        for pos in POSSIBLE_MSG_TYPES:
            cond = state.solver.Or(cond, var==pos)
        return cond

    module.symbolize_vendor(state, config)

    vars = list(state.solver.get_variables("message_buffer"))
    assert len(vars) == 1, "Number of BVS with prefix 'message_buffer' not 1."
    msg_buf = vars[0][1]

    vars = list(state.solver.get_variables("security_state"))
    assert len(vars) == 1, "Number of BVS with prefix 'security_state' not 1."
    sec_state = vars[0][1]

    sec_hdr1 = state.solver.BVS('security_header1', 4)
    pd1 = state.solver.BVS('protocol_discriminator1', 4)
    state.solver.register_variable(sec_hdr1, ("security_header1",0x1))
    state.solver.register_variable(pd1, ("protocol_discriminator1",0x1))
    state.solver.add(state.solver.Or(pd1 == 2, pd1 == 7))
    data = state.solver.Concat(sec_hdr1, pd1)
    state.memory.store(msg_buf, data)
    sec_hdr2 = state.solver.BVS('security_header2', 4)
    pd2 = state.solver.BVS('protocol_discriminator2', 4)
    state.solver.register_variable(sec_hdr2, ("security_header2",0x1))
    state.solver.register_variable(pd2, ("protocol_discriminator2",0x1))
    state.solver.add(state.solver.Or(pd2 == 2, pd2 == 7))
    data = state.solver.Concat(sec_hdr2, pd2)
    state.memory.store(msg_buf+6, data)

    msg_type1 = state.solver.BVS('msg_type1', 8)
    msg_type2 = state.solver.BVS('msg_type2', 8)
    msg_type3 = state.solver.BVS('msg_type3', 8)
    msg_type4 = state.solver.BVS('msg_type4', 8)
    state.solver.register_variable(msg_type1, ("msg_type1",0x1))
    state.solver.register_variable(msg_type2, ("msg_type2",0x1))
    state.solver.register_variable(msg_type3, ("msg_type3",0x1))
    state.solver.register_variable(msg_type4, ("msg_type4",0x1))
    state.memory.store(msg_buf+1, msg_type1)
    state.memory.store(msg_buf+2, msg_type2)
    state.memory.store(msg_buf+7, msg_type3)
    state.memory.store(msg_buf+8, msg_type4)
    msg_types = [msg_type1, msg_type2, msg_type3, msg_type4]
    for msg_type in msg_types:
        state.solver.add(create_msg_type_cond(msg_type))

def analyze_result(config, simgr, module):

    def has_irrelevant_constraint(s, syms):
        constraints = s.solver.simplify()
        has_unrelated = False
        for c in constraints:
            related = False
            for sym in syms:
                if is_related(c, sym):
                    related = True
            if related == False:
                has_unrelated = True

        if has_unrelated:
            return True
        
        return False

    def has_uspassed_state(s, syms):

        constraints = s.solver.simplify()
        rel_con = []
        for c in constraints:
            for sym in syms:
                if is_related(c, sym):
                    rel_con.append(c)

        checklist = []
        for s2 in simgr.found:
            if not module.acceptable(s2):
                checklist.append(s2)
        checklist = checklist+simgr.avoided

        for s2 in checklist:
            constraints2 = s2.solver.simplify()
            rel_con2 = []
            for c2 in constraints2:
                for sym in syms:
                    if is_related(c2, sym):
                        rel_con2.append(c2)
            if all(any(rc.structurally_match(x) for x in rel_con2) for rc in rel_con):
                    return True
        
        return False
    
    errors = []                 # element format: [sec_state, sec_hdr, pd, msg_type, reason(str)]
    errored_states = []         # element format: [state, reason(str)]
    considerable_states = []    # element format: [state, reason(str)]

    for s in simgr.found:
        # get symbolic variables from state
        msg_buf = list(s.solver.get_variables("message_buffer"))[0][1]
        sec_state = list(s.solver.get_variables("security_state"))[0][1]
        sec_hdr1 = list(s.solver.get_variables("security_header1"))[0][1]
        pd1 = list(s.solver.get_variables("protocol_discriminator1"))[0][1]
        sec_hdr2 = list(s.solver.get_variables("security_header2"))[0][1]
        pd2 = list(s.solver.get_variables("protocol_discriminator2"))[0][1]
        msg_type1 = list(s.solver.get_variables("msg_type1"))[0][1]
        msg_type2 = list(s.solver.get_variables("msg_type2"))[0][1]
        msg_type3 = list(s.solver.get_variables("msg_type3"))[0][1]
        msg_type4 = list(s.solver.get_variables("msg_type4"))[0][1]

        syms = [msg_buf, sec_state, sec_hdr1, pd1, sec_hdr2, pd2, msg_type1, msg_type2, msg_type3, msg_type4]

        if not module.acceptable(s):
            continue

        if has_irrelevant_constraint(s, syms):
            if has_uspassed_state(s, syms):
                continue

        try:
            # (INSECURE: 1, SECURE: 2)
            # is common for Samsung and Mediatek, 
            # but should we move the specific values (1 and 2) to the configuration?
            # TODO: will do
            pos_sec_state = s.solver.eval_one(sec_state)
        except angr.errors.SimValueError:
            # considering unconstrained security state case
            # -1 means that it can be either 1 or 2
            pos_sec_state = -1 #SEC_STATE_UNCONSTRAINED
        except:
            # not sure if there will be another exception
            # sec_state can't be anything ?
            considerable_states.append([s, "error with evaluating sec_state"])
            continue

        pos_sec_hdrs = s.solver.eval_upto(sec_hdr1, 16)
        
        for pos_sec_hdr in pos_sec_hdrs:
            if pos_sec_hdr == 0:
                try:
                    pos_pd = s.solver.eval_one(pd1)
                except angr.errors.SimUnsatError:
                    considerable_states.append([s, "no satisfiable PD"])
                    continue
                except angr.errors.SimValueError:
                    # Considering this exception as PD not constrained.
                    considerable_states.append([s, "PD can be both EMM and ESM"])
                    if s.solver.solution(pd1, 7):
                        pos_pd = 7
                        pass
                    else:
                        continue

                # Only considering EMM Messages
                if pos_pd != 7:
                    considerable_states.append([s, "PD is ESM"])
                    continue

                pos_msg_types = s.solver.eval_atmost(msg_type1, NUM_OF_POSSIBLE_MSG_TYPES)                
                if pos_sec_state == config['sec_state_insecure_value'] or pos_sec_state == -1:
                    # Considering TS 24.301 Sec 4.4.4.2
                    for pos_msg_type in pos_msg_types:
                        if pos_msg_type == 0x55:
                            # Identity Request: 0x55
                            # Check identity type
                            pos_id_type = s.solver.eval_atmost(msg_type2[2:0], 8)
                            if any(t_id_type in [2,3,4] for t_id_type in pos_id_type):
                                errors.append(['SEC_STATE_INSECURE', 0, 7, pos_msg_type, "Identity type can be {}".format(pos_id_type)])
                        elif pos_msg_type in [0x52, 0x54, 0x46]:
                            # Authentication Request: 0x52
                            # Authentication Reject: 0x54
                            # Detach Accept: 0x46
                            continue
                        elif pos_msg_type in [0x44, 0x4b, 0x4e]:
                            # Attach Reject: 0x44
                            # TAU Reject: 0x4b
                            # Service Reject: 0x4e
                            # Check EMM cause
                            if s.solver.solution(msg_type2, 25):
                                errors.append(['SEC_STATE_INSECURE', 0, 7, pos_msg_type, "EMM cause can be #25"])
                            pass
                        else:
                            # all other passing message types are considered misimplementations
                            errors.append(['SEC_STATE_INSECURE', 0, 7, pos_msg_type, "Invalid msg_type"])

                if pos_sec_state == config['sec_state_secure_value'] or pos_sec_state == -1:
                    for pos_msg_type in pos_msg_types:
                        errors.append(['SEC_STATE_SECURE', 0, 7, pos_msg_type, "Plaintext in SECURE state"])


            elif pos_sec_hdr == 1 or pos_sec_hdr == 3:
                try:
                    pos_pd = s.solver.eval_one(pd2)
                except angr.errors.SimUnsatError:
                    considerable_states.append([s, "no satisfiable PD"])
                    continue
                except angr.errors.SimValueError:
                    # Considering this exception as PD not constrained.
                    considerable_states.append([s, "PD can be both ESM and EMM"])
                    continue

                # Only considering EMM Messages
                if pos_pd != 7:
                    considerable_states.append([s, "PD is ESM, {}".format(pos_sec_hdr)])
                    continue

                pos_msg_types = s.solver.eval_atmost(msg_type3, NUM_OF_POSSIBLE_MSG_TYPES)

                for pos_msg_type in pos_msg_types:
                    if pos_sec_state == config['sec_state_insecure_value']:
                        errors.append(['SEC_STATE_INSECURE', pos_sec_hdr, 7, pos_msg_type, "Plaintext in sec_hdr=1 or 3, INSECURE"])
                    elif pos_sec_hdr == config['sec_state_secure_value']:
                        errors.append(['SEC_STATE_SECURE', pos_sec_hdr, 7, pos_msg_type, "Plaintext in sec_hdr=1 or 3, SECURE"])
                    elif pos_sec_hdr == -1:
                        errors.append(['SEC_STATE_INSECURE', pos_sec_hdr, 7, pos_msg_type, "Plaintext in sec_hdr=1 or 3, INSECURE"])
                        errors.append(['SEC_STATE_SECURE', pos_sec_hdr, 7, pos_msg_type, "Plaintext in sec_hdr=1 or 3, SECURE"])

            elif pos_sec_hdr == 2 or pos_sec_hdr == 4:
                errored_states.append([s, "sec_hdr value is {}, {}".format(pos_sec_hdr, pos_sec_state)])
                continue

            elif pos_sec_hdr == 0xc:
                errored_states.append([s, "sec hdr is 12, {}".format(pos_sec_state)])
                continue
            else:
                errored_states.append([s, "sec_hdr value can be invalid: {}, {}".format(pos_sec_hdr, pos_sec_state)])
                continue

    dedup_errors = []
    for error in errors:
        if error not in dedup_errors:
            dedup_errors.append(error)
    dedup_errors.sort()

    def concat_states(l):
        xxx = []
        for e in l:
            added = False
            for x in xxx:
                if e[0] == x[0]:
                    x.append(e[1])
                    added = True
            if added == False:
                xxx.append(e)
        return xxx        

    errored_states = concat_states(errored_states)
    considerable_states = concat_states(considerable_states)

    return dedup_errors, errored_states, considerable_states

def output(firmname, errors, errored_states, considerable_states, consumed_time):
    curtime = datetime.datetime.now().strftime('%m%d-%H%M%S')
    os.makedirs("results/{}".format(firmname), exist_ok=True)
    filename = "results/{}/{}.log".format(firmname, curtime)
    with open(filename, "a+") as f:
        f.write("Errored Results\n")
        for error in errors:
            f.write(str(error)+"\n")
        f.write("\n")

        f.write("Errored States\n")
        for es in errored_states:
            f.write(str(es)+"\n")
        f.write("\n")

        f.write("Considerable States\n")
        for cons in considerable_states:
            f.write(str(cons)+"\n")
        f.write("\n")

        f.write("Consumed Time: {}".format(consumed_time))

if __name__ == '__main__':
    st = time.time()
    config = get_config(args.firmconf, args.vendorconf, args.firmname)
    module = import_analysis(config['analysis'])
    proj, state = init(config)
    symbolize(state, config, module)
    module.add_hook_vendor(proj, state, config)

    simgr = proj.factory.simgr(state)
    if config['unconstrained']:
        simgr.use_technique(SkipUnconstrainedCalls())
    simgr.run(filter_func=create_filter_func(config))

    e, es, consid = analyze_result(config, simgr, module)
    en = time.time()
    consumed_time = en-st
    output(args.firmname, e, es, consid, consumed_time)