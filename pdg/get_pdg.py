import sys
import os
import time
import json
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.dvm import DalvikVMFormat
import networkx as nx
import numpy as np


class PDG:

    def __init__(self, dex, dv):
        self.dex = dex
        self.dv = dv
        self.pdg_graph = nx.DiGraph()

    # method description
    def get_method_description(self, method):

            return (method.get_class_name(),
                    method.get_name(),
                    method.get_descriptor())

    # basic block description
    def get_bb_description(self, bb):
            return self.get_method_description(bb.method) + (bb.name,)


    def get_children(self, bb):
            return self.get_inner_children(bb)  + self.get_outer_children(bb)


    def get_inner_children(self, bb):
            child_labels = []
            for child_bb in bb.get_next():
                next_bb = child_bb[2]
                child_labels.append(self.get_bb_description(next_bb))
            return child_labels


    # iterate over calls from bb method to external methods
    def get_outer_children(self, bb):
            call_labels = []

            try:
                xrefs = self.dex.get_method_analysis(bb.method).get_xref_to()
            except AttributeError:
                return call_labels

            for xref in xrefs:
                ref_method_idx = xref[2]
                if self.call_in_bb(bb, ref_method_idx):
                    try:
                        ref_method = self.dex.get_method(self.dv.get_method_by_idx(ref_method_idx))
                        if ref_method:
                            ref_bb = next(ref_method.basic_blocks.get())
                            call_labels.append(get_bb_description(ref_bb))
                    except StopIteration:
                        pass

            return call_labels


    def call_in_bb(self, bb, idx):
            return bb.get_start() <= idx <= bb.get_end()


    def get_pdg(self):
        for method in self.dex.get_methods():
            if method.is_external():
                continue
            else:
                methodAnalysis = self.dex.get_method(method.get_method())
                for basicBlock in methodAnalysis.get_basic_blocks().gets():
                    children = []
                    description = self.get_bb_description(basicBlock)
                    children = self.get_children(basicBlock)
                    self.pdg_graph.add_node(description)
                    self.pdg_graph.add_edges_from([(description, child) for child in children])

        return self.pdg_graph
