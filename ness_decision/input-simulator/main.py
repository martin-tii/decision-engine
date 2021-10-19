import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
import random
from random import choices
import pickle
import argparse

# Construct the argument parser
ap = argparse.ArgumentParser()


# Add the arguments to the parser
ap.add_argument("-d", "--dataset", required=True, help="Dataset topology")
args = ap.parse_args()


def read_file(file):
    return nx.read_gml(file)


def plot(G):
    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, cmap=plt.get_cmap('jet'), node_size=500)
    nx.draw_networkx_labels(G, pos)
    nx.draw_networkx_edges(G, pos, arrows=False)
    plt.show(block=False)


def get_neighbors(G):
    neighs = {node: [neig for neig in nx.neighbors(G, node)] for node in G.nodes()}
    print('Neighbors: ')
    print(neighs)
    return neighs


def mapping(G):
    # mapp = dict(zip(range(len(G.nodes())), G.nodes()))
    mapp = dict(zip(topo.nodes(), range(len(topo.nodes()))))
    print("Map node labels with ID ")
    print(mapp)
    return nx.relabel_nodes(G, mapp)


def create_flags(G, node, mal):
    flags = []
    population = [1, 3]  # possible flags
    weight = [0.99, 0.01]  # 3 should have a very low probability
    if node not in mal:
        for _ in range(len(list(nx.neighbors(G, node)))):
            flags.append(choices(population, weight)[0])
    else:
        for _ in range(len(list(nx.neighbors(G, node)))):
            flags.append(2)
    return flags


def gets_status(flags):
    voting = np.unique(flags, return_counts=True)
    if flags.count(1) == flags.count(2):  # if equal number of occurrence between 1 and 2 then results is 3
        return 3
    if len(voting[0]) > 1:
        return voting[0][np.argmax(voting[1])]
    else:
        return voting[0][0]


def get_malicious(G, num_mal):
    mal = []
    for _ in range(num_mal):
        node = random.choice(list(G.nodes()))
        mal.append(node)
    print('Malicious Nodes: ', mal)
    return mal


def create_tuple(G, num_mal):
    output = []
    mal = get_malicious(G, num_mal)
    for node in G.nodes():
        aux = []
        aux.append(node)
        flags = create_flags(G, node, mal)
        aux.append(flags)
        status = gets_status(flags)
        aux.append(status)
        output.append(aux)
    return output


if __name__ == '__main__':
    topo = read_file(args.dataset)  # open file
    get_neighbors(topo)  # get the name neighbors (only to print)
    new_topo = mapping(topo)  # map names with IDs
    neighbors = get_neighbors(new_topo)  # now getting the real neighbors
    val = input("Enter number of malicious nodes: ")
    output = create_tuple(new_topo, int(val))
    print('Final List: ')
    print(output)
    with open('output.data', 'wb') as filehandle:
        # store the data as binary data stream
        pickle.dump(output, filehandle, pickle.HIGHEST_PROTOCOL)
