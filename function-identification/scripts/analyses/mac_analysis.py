# pylint: disable=wildcard-import, unused-wildcard-import
from itertools import product
from .utils import *

SNOW_SBOX_SIG = "63 7C 77 7B"
ZUC_SBOX_SIG  = "55 c2 63 71"

class MACAnalysis(object):
    def find_sbox(self, target):
        lst = []
        ea_t = 0

        while True:
            ea_t = ida_search.find_binary(ea_t, idc.BADADDR, target, 16, idc.SEARCH_DOWN)
            if ea_t == idc.BADADDR:
                break
            lst.append(ea_t)
            ea_t += 256

        t = []
        for ea in lst:
            xrefs = idautils.XrefsTo(ea, 1)
            for xref in xrefs:
                frm = xref.frm
                f_ea = idc.get_func_attr(frm, idc.FUNCATTR_START)
                if f_ea != 0xffffffff:
                    t.append(f_ea)

        return list(set(t))

    def do_intersection(self, G, CD, snow_refs, zuc_refs):
        snow_indices = [CD.fea_to_idx(ea) for ea in snow_refs]
        zuc_idices = [CD.fea_to_idx(ea) for ea in zuc_refs]

        # Add a common ancestor to the graph
        for i in range(CD.get_length()):
            def add_factor():
                for snow_i, zuc_i in product(snow_indices, zuc_idices):
                    if CD.is_caller(i, snow_i, limit=MAXCALLDISTANCE) \
                        and CD.is_caller(i, zuc_i, limit=MAXCALLDISTANCE):
                        add_factor_a(G, CD.idx_to_fea(i), BASE_P*1*1)
                        return
            add_factor()

        # Prioritize the lower common ancestor
        for n1, n2 in product(G.get_variable_nodes(), G.get_variable_nodes()):
            if n1 == n2:
                continue

            if CD.is_caller(CD.fea_to_idx(n1), CD.fea_to_idx(n2), limit=MAXCALLDISTANCE):
                add_factor_b(G, n1, n2)

    @cache.cache("mac_analysis")
    def analyze(self, CD):
        G = FactorGraph()
        
        snow_refs = self.find_sbox(SNOW_SBOX_SIG)
        zuc_refs = self.find_sbox(ZUC_SBOX_SIG)

        self.do_intersection(G, CD, snow_refs, zuc_refs)

        # Make a connected graph
        nnnn = G.get_variable_nodes()
        G.add_node('root')
        for node in nnnn:
            add_factor_x(G, 'root', node)

        G.check_model()

        bp = BeliefPropagation(G)
        bp.calibrate()

        # Getting priority of each node
        mac_targets = []
        for node in G.get_variable_nodes():
            if node == 'root':
                continue
            res = bp.query(variables=[node], show_progress=False)
            mac_targets.append([node, res.values[1]])

        mac_targets.sort(key=lambda x : x[1], reverse=True)
        return mac_targets