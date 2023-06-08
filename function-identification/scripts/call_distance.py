import idautils
import ida_funcs
import networkit as nk

FEA_TO_IDX = 0
IDX_TO_FEA = 1

class CallDistance():
    def __init__(self):
        self.mapping = {}

        for i, func_ea in enumerate(idautils.Functions()):
            self.mapping[(IDX_TO_FEA, i)] = func_ea
            self.mapping[(FEA_TO_IDX, func_ea)] = i

        self.initialize_apsp()

    def initialize_apsp(self):
        G = self.make_graph()
        self.apsp = nk.distance.APSP(G)
        self.apsp.run()

    def make_graph(self):
        G = nk.Graph(self.get_length(), weighted=False, directed=True)
        for func_ea in idautils.Functions():
            for xref in idautils.XrefsTo(func_ea, 0):
                if xref.type == 17 or xref.type == 19: # jump and call
                    if ida_funcs.get_func(xref.frm) is not None:
                        caller_fea = ida_funcs.get_func(xref.frm).start_ea
                        callee_fea = func_ea
                        if self.fea_to_idx(caller_fea) == -1:
                            continue
                        if self.fea_to_idx(callee_fea) == -1:
                            continue

                        G.addEdge(self.fea_to_idx(caller_fea), self.fea_to_idx(callee_fea))
        return G

    def get_length(self):
        return len(self.mapping) // 2

    def is_caller(self, i, j, limit=10000000):
        return self.apsp.getDistance(i,j) <= limit

    def get_distance(self, i, j):
        return self.apsp.getDistance(i, j)

    def idx_to_fea(self, idx):
        return self.mapping[(IDX_TO_FEA, idx)]

    def fea_to_idx(self, fea):
        return self.mapping[(FEA_TO_IDX, fea)]
