import sys
import os
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from pdg_construction import PDG
import networkx as nx


if len(sys.argv) != 2:
    print('Usage: get_graph.py <apk_path>')
    sys.exit()

apk_file = sys.argv[1]


def get_analysis_objects(apk_file):
    apk, dvm, dex = AnalyzeAPK(apk_file)
    dvm_analysis = DalvikVMFormat(apk.get_dex())
    return dex, dvm_analysis


def get_pdg(dex, dvm_analysis, pdg_graph):
    for method in dex.get_methods():
        if method.is_external():
            continue
        else:
            methodAnalysis = dex.get_method(method.get_method())
            for basicBlock in methodAnalysis.get_basic_blocks().gets():
                children = []
                description = get_bb_description(basicBlock)
                children = get_children(basicBlock, dex, dvm_analysis)
                pdg_graph.add_node(label)
                pdg_graph.add_edges_from([(label, child) for child in children])

    return pdg_graph


def construct(apk_file):
    dex, dvm_analysis = get_analysis_objects(apk_file)
    pdg_i = PDG(dex, dvm_analysis)
    pdg_g = pdg_i.get_pdg()
    return pdg_g


try:
    pdg_graph = construct(apk_file)
    nx.write_gpickle(pdg_graph, "pdg_" + os.path.basename(apk_file))
except:
     print("Error generating the PGD")
finally:
    print("Successfully saved under "+ os.path.dirname(os.path.realpath(apk_file)))
