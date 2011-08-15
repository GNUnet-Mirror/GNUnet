from __future__ import print_function
import os
import re
import sys

debug = False

def get_td_from_function_signature (line, file, num):
  left_paren = line.find ('(')
  if left_paren > 0:
    left_paren += 1
    line = line[left_paren:]
    right_paren = line.find (')')
    if right_paren > 0 and right_paren > left_paren and line[right_paren:].find ('(') >= 0:
      fname = line[:right_paren]
      fname = fname.lstrip (' ').lstrip ('*').lstrip (' ').rstrip (' ')
      if len (fname) > 0:
        if debug:
          print ("from {0}:{1}".format (file, num))
        print ("-T {0}".format (fname))

def get_td_from_simple_type (line, file, num):
  line = line.rstrip (' ').rstrip ('\t').rstrip (' ').rstrip ('\t')
  right_space = line.rfind (' ')
  right_tab = line.rfind ('\t')
  sep = right_tab if right_tab > right_space else right_space
  sep += 1
  tname = line[sep:]
  tname = tname.lstrip ('*')
  if len (tname) > 0:
    if debug:
      print ("from {0}:{1}".format (file, num))
    print ("-T {0}".format (tname))

def find_typedefs (file):
  with open (file, 'rb') as f:
    td = False
    td_struct = False
    td_level = 0
    td_line = []
    data = f.read ()
    for i, l in enumerate (data.splitlines (False)):
      # Don't try to be too smart: only count lines that begin with 'typedef '
      l = l.rstrip (' ').rstrip ('\t')
      if len (l) == 0:
        continue
      if not td:
        if l[:8] != 'typedef ':
          continue
        else:
          td = True
          if l[8:].lstrip (' ').lstrip ('\t')[:6] == 'struct':
            td_struct = True
      if td_struct:
        leftcbrace = l.find ('{')
        if leftcbrace >= 0:
          if td_level == 0:
            td_line.append (l[:leftcbrace])
          l = l[leftcbrace + 1:]
          td_level += 1
        rightcbrace = l.rfind ('}')
        if rightcbrace >= 0:
          td_level -= 1
          if td_level == 0:
            td_line.append (l[rightcbrace + 1:])
      else:
        td_line.append (l)
      if len (l) > 0 and l[-1] == ';' and (not td_struct or td_level == 0):
        td_line = ' '.join (td_line)
        td_line = td_line[:-1]
        if len (td_line) > 0:
          if td_line[-1] == ')':
            get_td_from_function_signature (td_line, file, i)
          else:
            get_td_from_simple_type (td_line, file, i)
        td_line = []
        td = False
        td_struct = False
        td_level = 0
      

def scan_dir (d):
  for dirpath, dirs, files in os.walk (d):
    for f in files:
      if re.match (r'(?!lt_).+\.(c|cc|h)$', f):
        file = os.path.join (dirpath, f)
        find_typedefs (file)


if __name__ == '__main__':
  if len (sys.argv[1:]) == 0:
    arg = os.getcwd ()
  else:
    arg = sys.argv[1]
  scan_dir (arg)