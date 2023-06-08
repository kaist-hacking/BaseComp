import logging

import idautils

import ida_funcs
import ida_hexrays as idahr

# pylint: disable=wildcard-import, unused-wildcard-import
from .utils import *

l = logging.getLogger(__name__)
l.setLevel(logging.INFO)

class IntegrityFunctionAnalysis(object):
    @cache.cache("integrity_function_analysis")
    def analyze(self, CD, mac_targets, msg_type_targets):
        G = FactorGraph()

        self.do_intersection(G, CD, mac_targets, msg_type_targets)

        d = dict()
        for node in G.get_factor_nodes():
            for var in node.variables:
                if var in d:
                    d[var] = d[var] + 1
                else:
                    d[var] = 1

        l.info(str(d))

        nnnn = G.get_variable_nodes()

        # append disjoint graphs by adding factor between root? nodes
        # maybe change this to connecting all to one
        G.add_node('root')
        for node in nnnn:
            add_factor_x(G,'root',node)

        # get marginal probability for each node and line it up
        G.check_model()

        bp = BeliefPropagation(G)
        bp.calibrate()

        integ_probs = []

        for node in G.get_variable_nodes():
            if node == 'root':
                continue
            l.info("querying for {}".format(node))
            try:
                res = bp.query(variables=[node], show_progress=False)
                integ_probs.append([node,res.values[1]])
            except:
                continue

        integ_probs.sort(key=lambda x : x[1], reverse=True)
        return integ_probs

    def do_intersection(self, G, CD, mac_targets, msg_type_targets):

        mac_idxs, msg_type_idxs = [], []

        for target in mac_targets:
            mac_idxs.append([CD.fea_to_idx(target[0]),target[1]])

        for target in msg_type_targets:
            msg_type_idxs.append([CD.fea_to_idx(target[0]),target[1]])

        new_nodes = []

        for i in range(CD.get_length()):
            def do():
                for mac_i in mac_idxs:
                    for msg_i in msg_type_idxs:
                        if CD.is_caller(i, mac_i[0], limit=MAXCALLDISTANCE) \
                            and CD.is_caller(i, msg_i[0], limit=MAXCALLDISTANCE):
                            l.info(hex(CD.idx_to_fea(i)) + " calls " + hex(CD.idx_to_fea(mac_i[0])) + " and " + hex(CD.idx_to_fea(msg_i[0])))
                            add_factor_a(G, CD.idx_to_fea(i), BASE_P*mac_i[1]*msg_i[1])
                            #new_nodes.append([i, mac_i[0], msg_i[0]])
                            return
            do()

        # for added nodes in graph, check if positive iscaller value exists -> add factor_b
        for n1 in G.get_variable_nodes():
            for n2 in G.get_variable_nodes():
                if n1 == n2:
                    continue
                if CD.is_caller(CD.fea_to_idx(n1),CD.fea_to_idx(n2), limit=MAXCALLDISTANCE):
                    l.info("{} calls {}".format(n1, n2))
                    add_factor_b(G, n1, n2)