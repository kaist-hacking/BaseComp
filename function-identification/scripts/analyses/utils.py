# pylint: disable=unused-import
import idc
import ida_search
import idautils

from pgmpy.models import FactorGraph
from pgmpy.inference import BeliefPropagation
from pgmpy.factors.discrete import DiscreteFactor
from .cache import cache

# EDIT THE FOLLOWING LINE TO CHANGE THE PROBABILITY PARMETER
PROBABILITY_PARAMETER = 0.2

MAXCALLDISTANCE = 7
BASE_P = 1-PROBABILITY_PARAMETER
REDUCED_P = (BASE_P-0.5)/2 + 0.5

def add_factor_a(G, n, p):
    G.add_node(n)
    pt = [1-p, p]
    add_single_node_factor(G, n, pt)

def add_factor_b(G, n1, n2):
    #TODO: check if n1, n2 are in G
    p = BASE_P
    pt = [0.5, p, 1-p, 0.5]
    add_two_node_factor(G, n1, n2, pt)

def add_factor_c(G, n1, n2, p):
    pt = [0.5, 0.5, 1-p, p]
    add_two_node_factor(G, n1, n2, pt)

def add_factor_d(G, n1, n2, p):
    pt = [0.5, 0.5, p, 1-p]
    add_two_node_factor(G, n1, n2, pt)

def add_factor_x(G, n1, n2):
    #TODO: check if n1, n2 are in G
    pt = [0.5, 0.5, 0.5, 0.5]
    add_two_node_factor(G, n1, n2, pt)

def add_single_node_factor(G, n, pt):
    '''
    :param n:       Name of node.
    :param pt:      Probability table.
        [#1, #2]
                n
        #1 :    F
        #2 :    T
    '''
    f = DiscreteFactor([n], [2], pt)
    G.add_factors(f)
    G.add_edge(n, f)

def add_two_node_factor(G, n1, n2, pt):
    '''
    :param n1:      Name of first node.
    :param n2:      Name of second node.
    :param pt:      Probability table.
        [#1, #2, #3, #4]
                n1      n2
        #1 :    F       F
        #2 :    F       T
        #3 :    T       F
        #4 :    T       T
    '''
    f = DiscreteFactor([n1, n2], [2, 2], pt)
    G.add_factors(f)
    G.add_edges_from([(n1, f),(n2, f)])