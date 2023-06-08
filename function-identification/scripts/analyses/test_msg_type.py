import idautils
import ida_funcs
import ida_hexrays as idahr

from pgmpy.models import FactorGraph
from pgmpy.inference import BeliefPropagation
from pgmpy.factors.discrete import DiscreteFactor

class MsgTypeNode():
    def __init__(self, f_ea, mop, prob):
        # dstr is mop.dstr() of mop
        self.f_ea = f_ea
        self.mop = mop
        self.prob = prob
        self.lvar = None

        if self.mop.l is not None:
            self.lvar = self.mop.l.var()

    def __str__(self) -> str:
        s = "<"
        s += "f: " + hex(self.f_ea)
        s += " // "
        if self.lvar is not None:
            s += "{}[{}]".format(self.mop.dstr(), self.lvar.name)
        else:
            s += "{}[]".format(self.mop.dstr())
        s += " -> "
        s += str(self.prob)
        s += ">"
        return s

class Values(): 
    # value lists
    # list to store values compared to mop_t
    def __init__(self, mop):
        self._mop = mop
        self._vals = []
    
    def add_val(self, val):
        if val not in self._vals:
            self._vals.append(val)
    
    def eq_mop(self, mop):
        return self._mop.equal_mops(mop, idahr.EQ_IGNSIZE)

class ValuesList():
    # list of vls
    def __init__(self):
        self._list = []

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)
    
    def has_mop(self, mop):
        for vl in self._list:
            if vl.eq_mop(mop):
                return True
        return False

    def add_v2vl(self, mop, val):
        for vl in self._list:
            if vl.eq_mop(mop):
                vl.add_val(val)
    
    def add_mop(self, mop):
        self._list.append(Values(mop))

    # TODO: dependency between mops

class cmp_collector_t(idahr.minsn_visitor_t):
    def __init__(self, magics):
        idahr.minsn_visitor_t.__init__(self)
        self.magics = magics
        
        self.res = ValuesList()
        self.G = None
        self.mop_list = []
        self.probs = None

    def visit_minsn(self):
        ins = self.curins
        
        print(ins.dstr())

        # handling opcode type m_jz, m_jnz
        if ins.opcode in [idahr.m_jz, idahr.m_jnz]:
            l,r = ins.l, ins.r

            if r.is_constant(True):
                val = r.value(True)
            else:
                return 0

            if not self.res.has_mop(l):
                self.res.add_mop(l)
            self.res.add_v2vl(l, val)

        # handling opcode type m_jtbl (jump table)
        if ins.opcode == idahr.m_jtbl:
            l,r = ins.l,ins.r
            cases = r.c

            if not self.res.has_mop(l):
                self.res.add_mop(l)

            for i in cases.values:
                for j in i:
                    self.res.add_v2vl(l,j)

        return 0
    
    def print_res(self):
        for vl in self.res:
            print(vl._mop.dstr())
            print(vl._vals)

    def dump_res(self,file):
        for vl in self.res:
            file.write(vl._mop.dstr() + ": " + str(vl._vals) + "\n")

    def should_gen(self):        
        # don't if there's nothing in res
        if len(self.res) == 0:
            return False
        # don't if none of the values match magic
        for vl in self.res:
            for val in vl._vals:
                if val in self.magics:
                    return True
        return False

    def gen_factor_graph(self):

        if not self.should_gen():
            return 0

        self.G = FactorGraph()

        # first add var nodes
        # then add cmp nodes
        for vl in self.res:
            self.G.add_node(vl._mop.dstr())
            self.mop_list.append(vl._mop)
            for val in vl._vals:
                self.add_factor_a(vl._mop.dstr(), val)

        # connect var nodes to function node for no no sepset errors
        self.G.add_node("f")
        for mop in self.mop_list:
            f = DiscreteFactor(["f", mop.dstr()], [2,2], [0.5, 0.5, 0.5, 0.5])
            self.G.add_factors(f)
            self.G.add_edges_from([("f",f), (mop.dstr(),f)])

        try:
            self.G.check_model()

            bp = BeliefPropagation(self.G)
            bp.calibrate()

            self.probs = []

            for mop in self.mop_list:
                res = bp.query(variables=[mop.dstr()], show_progress=False)
                self.probs.append([mop, res.values[1]]) 

            self.probs.sort(key=lambda x : x[1], reverse=True)
            
            return 1
        
        except ValueError:
            self.probs = None
            return -1

    def dump_probs(self,file):
        if self.probs == []:
            return
        file.write(str(self.probs)+"\n")

    def add_factor_a(self, mop, val):
        node_name = "{}_cmp_{}".format(mop, str(val))
        self.G.add_node(node_name)
        f1 = DiscreteFactor([node_name], [2], [0, 1])

        if val in self.magics:
            p = 0.8 # BASE_P            
            f2 = DiscreteFactor([node_name, mop], [2,2], [0.5, 0.5, 1-p, p])
        else:
            p = (0.8-0.5)/2 + 0.5 #(BASE_P-0.5)/2 + 0.5
            f2 = DiscreteFactor([node_name, mop], [2,2], [0.5, 0.5, p, 1-p])
        
        self.G.add_factors(f1, f2)
        self.G.add_edges_from([(node_name, f1), (node_name, f2), (mop, f2)])

    def filter_probs(self, threshold):
        # return [i for i in self.probs if i[1] > threshold]
        filtered = []
        for i in self.probs:
            if i[1] > threshold:
                filtered.append(i)
        return filtered

class MsgTypeAnalysis():
    def __init__(self, magics, threshold) -> None:
        self.magics = magics
        self.gen_fail_list = []
        self.msg_type_nodes = []
        self.threshold = threshold
        self.cc = None

        self.collect()

    def collect(self):
        #targets = idautils.Functions()
        targets = [0x9047ffc0]
        for func_ea in targets:
            func = ida_funcs.get_func(func_ea)
            ht  = idahr.hexrays_failure_t()
            cfunc = idahr.decompile_func(func, ht)

            print(ht.errea)
                    
            if ht.errea == 0xffffffff or ht.errea == 0xffffffffffffffff:
                print("making cc")
                self.cc = cmp_collector_t(self.magics)
                print("made cc")
                cfunc.mba.for_all_insns(self.cc)
                print("ran for al insns")



                # probabilistic reasoning
                '''res = cc.gen_factor_graph()
                if  res == 1:
                    filtered = cc.filter_probs(self.threshold)
                    for i in filtered:
                        self.msg_type_nodes.append(MsgTypeNode(func_ea, i[0], i[1]))
                elif res == -1:
                    self.gen_fail_list.append(func_ea)'''
            else:
                self.cc = 1

    def get_results(self):
        return self.msg_type_nodes

    def analyze(self):
        self.collect()

        msg_type_targets = []
        for node in self.get_results():
            if node.lvar is not None:
                msg_type_targets.append([node.f_ea, node.lvar.name, node.prob])

        msg_type_targets.sort(key=lambda x : x[2], reverse=True)
        return msg_type_targets

def main():
    filename = "msg_type_test"
    file = open(filename, "w")

    magics = [0x55, 0x44, 0x4b, 0x4e, 0x52, 0x54, 0x46]

    MTV = MsgTypeAnalysis(magics, 0)

    for vl in MTV.cc.res:
        file.write("mop: ")
        file.write(str(vl._mop.dstr()))
        file.write("\n")

        file.write("values: ")
        file.write(str(vl._vals))
        file.write("\n")

    file.close()

    #ida_pro.qexit(0)

if __name__ == "__main__":
    main()