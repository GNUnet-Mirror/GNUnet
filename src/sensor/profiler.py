import argparse
import math
import networkx
import random
import tempfile
import os
import time
import matplotlib.pyplot as plt
from subprocess import Popen, PIPE, STDOUT

node_colors = None
graph = None
pos = None

def get_args():
  parser = argparse.ArgumentParser(description="Sensor profiler")
  parser.add_argument('-p', '--peers', action='store', type=int, required=True,
                      help='Number of peers to run')
  parser.add_argument('-i', '--sensors-interval', action='store', type=int,
                      required=False,
                      help='Change the interval of running sensors to given value')
  return parser.parse_args()

def generate_topology(peers, links):
  global graph
  global node_colors
  global pos
  graph = networkx.empty_graph(peers)
  for i in range(0, links):
    a = 0
    b = 0
    while a == b:
      a = random.randint(0, peers - 1)
      b = random.randint(0, peers - 1)
    graph.add_edge(a, b)
  node_colors = [0] * peers
  pos = networkx.layout.spring_layout(graph)

def create_topology_file():
  global graph
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

def draw_graph():
  global graph
  global node_colors
  global pos
  t = int(time.time())
  inc = 2
  name = str(t) + '.png'
  while os.path.exists(name):
    name = '%d(%d).png' % (t, inc)
    inc += 1
  print 'Drawing graph to file: %s' % name
  plt.clf()
  networkx.draw(graph, pos=pos, node_color=node_colors, with_labels=range(len(graph.node)), cmap=plt.cm.Reds, vmin=0, vmax=2)
  plt.savefig(name)

def peers_disconnected(p1, p2):
  global graph
  print 'Disconnected peers %d and %d' % (p1, p2)
  if p2 not in graph[p1]:
    print 'Link does not exist'
    return
  graph.remove_edge(p1, p2)
  draw_graph()

def anomaly_report(report):
  global node_colors
  if 0 == report['anomalous']:
    node_colors[report['peer']] = 0
  else:
    node_colors[report['peer']] = 1 + report['neighbors']
  draw_graph()

def handle_profiler_line(line):
  if not line:
    return
  print line
  if 'Peer disconnection request sent' in line: # Peers disconnected
    parts = line.split(':')
    peers = parts[-1].split(',')
    peers_disconnected(int(peers[0]), int(peers[1]))
    return
  if 'Anomaly report:' in line:
    parts = line.split('Anomaly report:')
    anomaly_report(eval(parts[1]))
    return

def run_profiler(peers, topology_file, sensors_interval):
  cmd1 = "GNUNET_FORCE_LOG='gnunet-sensor-profiler;;;;DEBUG' gnunet-sensor-profiler -p %d -t %s" % (peers, topology_file)
  if sensors_interval:
    cmd1 += " -i %d" % sensors_interval
  cmd2 = "> log 2>&1"
  cmd = "%s %s" % (cmd1, cmd2)
  print cmd
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
  sensors_interval = None
  if 'sensors_interval' in args:
    sensors_interval = args['sensors_interval']
  #num_links = int(math.log(num_peers) * math.log(num_peers) * num_peers / 2)
  num_links = int(math.log(num_peers) * num_peers)
  # Generate random topology
  generate_topology(num_peers, num_links)
  print 'Generated random topology with %d peers and %d links' % (num_peers, num_links)
  # Create TESTBED topology file
  top_file = create_topology_file()
  print 'Created TESTBED topology file %s' % top_file
  draw_graph()
  # Run c profiler
  run_profiler(num_peers, top_file, sensors_interval)
  
if __name__ == "__main__":
  main()
