import argparse
import math
import networkx
import random
import tempfile
import os
import time
from subprocess import Popen, PIPE, STDOUT

def get_args():
  parser = argparse.ArgumentParser(description="Sensor profiler")
  parser.add_argument('-p', '--peers', action='store', type=int, required=True,
                      help='Number of peers to run')
  return parser.parse_args()

def generate_topology(peers, links):
  G = networkx.empty_graph(peers)
  for i in range(0, links):
    a = 0
    b = 0
    while a == b:
      a = random.randint(0, peers)
      b = random.randint(0, peers)
    G.add_edge(a, b)
  return G

def create_topology_file(graph):
  nodes = list()
  for i in range(len(graph.edge)):
    nodes.append(list())
  for e in graph.edges():
    nodes[e[0]].append(e[1])
  print nodes
  f = tempfile.NamedTemporaryFile(delete=False)
  for i in range(len(nodes)):
    if len(nodes[i]) == 0:
      continue
    f.write('%d:' % i)
    f.write('|'.join(map(str, nodes[i])))
    f.write('\n')
  # f.close()
  return f.name

def handle_profiler_line(line):
  if not line:
    return
  print line

def run_profiler(peers, topology_file):
  cmd = "GNUNET_FORCE_LOG='gnunet-sensor-profiler;;;;DEBUG' gnunet-sensor-profiler -p %d -t %s > log 2>&1" % (peers, topology_file)
  process = Popen([cmd], shell=True)
  time.sleep(0.5)
  line = ''
  f = open('log')
  while process.poll() is None:
    for c in f.read():
      if not c or c == '\n':
        handle_profiler_line(line)
        line = ''
      else:
        line += c
  os.remove('log')

def main():
  args = vars(get_args())
  num_peers = args['peers']
  if num_peers < 3:
    print 'Min number of peers is 3'
    return
  num_links = int(math.log(num_peers) * math.log(num_peers) * num_peers / 2)
  # Generate random topology
  graph = generate_topology(num_peers, num_links)
  print 'Generated random topology with %d peers and %d links' % (num_peers, num_links)
  # Create TESTBED topology file
  top_file = create_topology_file(graph)
  print 'Created TESTBED topology file %s' % top_file
  # Run c profiler
  run_profiler(num_peers, top_file)
  
if __name__ == "__main__":
  main()
