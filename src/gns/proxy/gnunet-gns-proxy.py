#!/usr/bin/python

"""
Copyright (c) 2001 SUZUKI Hisao 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: 

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

__doc__ = """Tiny HTTP Proxy.

This module implements GET, HEAD, POST, PUT and DELETE methods
on BaseHTTPServer, and behaves as an HTTP proxy.  The CONNECT
method is also implemented experimentally, but has not been
tested yet.

Any help will be greatly appreciated.   SUZUKI Hisao
"""

__version__ = "0.2.1"

import BaseHTTPServer, select, socket, SocketServer, urlparse, re, string, os, sys

class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle

    server_version = "TinyHTTPProxy/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered
    host_port = ()

    def handle(self):
        (ip, port) =  self.client_address
        if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request(): self.send_error(403)
        else:
            self.__base_handle()

    def _connect_to(self, netloc, soc):
        i = netloc.find(':')
        to_replace = ""
        if i >= 0:
          self.host_port = netloc[:i], int(netloc[i+1:])
          if (re.match("(\w+\.)*gnunet$", self.host_port[0])):
            print 'calling gnunet-gns -a '+netloc[:i]
            auth = os.popen("gnunet-gns -a "+netloc[:i])
            lines = auth.readlines()
            if (len(lines) > 0):
              print 'result: '+lines[0].split(" ")[-1].rstrip()
              to_replace = lines[0].split(" ")[-1].rstrip()
            else:
              to_replace = "+"
        else:
          self.host_port = netloc, 80
          if (re.match("(\w+\.)*gnunet$", self.host_port[0])):
            print 'calling gnunet-gns -a '+netloc
            auth = os.popen("gnunet-gns -a "+netloc)
            lines = auth.readlines()
            if (len(lines) > 0):
              print 'result: '+lines[0].split(" ")[-1].rstrip()
              to_replace = lines[0].split(" ")[-1].rstrip()
            else:
              to_replace = "+"

        print "\t" "connect to %s:%d" % self.host_port
        try: soc.connect(self.host_port)
        except socket.error, arg:
            try: msg = arg[1]
            except: msg = arg
            self.send_error(404, msg)
            return (0, 0)
        return (1, to_replace)

    def do_CONNECT(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            res, to_repl = self._connect_to(self.path, soc)
            if res:
                self.log_request(200)
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                self._read_write(soc, to_repl, 300)
        finally:
            print "\t" "bye"
            soc.close()
            self.connection.close()
    
    def test_re2(self, mo):
      short = os.popen("gnunet-gns -s"+string.replace(mo.group(1), 'a href="http://', ""))
      lines = short.readlines()
      if (len(lines) < 1):
        return mo.group(1)
      elif (len(lines[0].split(" ")) > 0):
        return 'a href="http://'+lines[0].split(" ")[-1].rstrip()
      else:
        return mo.group(1)

    def shorten_zkey(self):
      return lambda mo: self.test_re2(mo)
      #return lambda mo: 'a href="http://'+os.popen("gnunet-gns -s"+string.replace(mo.group(1), 'a href="http://', "")).readlines()[0].split(" ")[-1].rstrip()
    
    def test_re(self, to_repl, mo):
      short = os.popen("gnunet-gns -s "+string.replace(mo.group(1)+to_repl, 'a href="http://', ""))
      lines = short.readlines()
      if (len(lines) < 1):
        return to_repl
      elif (len(lines[0].split(" ")) > 0):
        return 'a href="http://'+lines[0].split(" ")[-1].rstrip()
      else:
        return to_repl

    def replace_and_shorten(self, to_repl):
      return lambda mo: self.test_re(to_repl, mo)
    #  return lambda mo: 'a href="http://'+os.popen("gnunet-gns -s "+string.replace(mo.group(1)+to_repl, 'a href="http://', "")).readlines()[0].split(" ")[-1].rstrip()
    #full = string.replace(mo.group(1)+to_repl, 'a href="http://', "")
        #print 'calling gnunet-gns -s '+full
        #s = os.popen("gnunet-gns -s "+full)
        #lines = s.readlines()
        #print 'short: '+lines[0].split(" ")[-1].rstrip()
        #return 'a href="'+lines[0].split(" ")[-1].rstrip()

    def do_GET(self):
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        if scm != 'http' or fragment or not netloc:
            self.send_error(400, "bad url %s" % self.path)
            return
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            res, to_repl = self._connect_to(netloc, soc)
            if res:
                self.log_request()
                soc.send("%s %s %s\r\n" % (
                    self.command,
                    urlparse.urlunparse(('', '', path, params, query, '')),
                    self.request_version))
                if (re.match("(\w+\.)*gnunet$", self.headers['Host'])):
                  leho = os.popen("gnunet-gns -t LEHO -u "+self.headers['Host']).readlines()
                  if (len(leho) < 2):
                    print "Legacy hostname lookup failed!"
                  elif (len(leho) == 1):
                    print "Legacy hostname not present!"
                  else:
                    newhost = leho[1].split(" ")[-1].rstrip()
                    print "Changing Host: "+self.headers['Host']+" to "+newhost
                    self.headers['Host'] = newhost
                self.headers['Connection'] = 'close'
                del self.headers['Proxy-Connection']
                del self.headers['Accept-Encoding']
                for key_val in self.headers.items():
                    soc.send("%s: %s\r\n" % key_val)
                soc.send("\r\n")
                self._read_write(soc, to_repl)
        finally:
            print "\t" "bye"
            soc.close()
            self.connection.close()

    def _read_write(self, soc, to_repl="", max_idling=20):
        iw = [self.connection, soc]
        ow = []
        count = 0
        msg = ''
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 3)
            if exs:
              break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                    else:
                        out = soc
                    data = i.recv(8192)
                    if data:
                        #try:
                          data = re.sub(r'\nAccept-Ranges: \w+', r'', data)
                          data = re.sub('(a href="http://(\w+\.)*zkey)',
                              self.shorten_zkey(), data)
                          if (re.match("(\w+\.)*gnunet$", self.host_port[0])):
                              arr = self.host_port[0].split('.')
                              arr.pop(0)
                              data = re.sub('(a href="http://(\w+\.)*)(\+)',
                                  self.replace_and_shorten(to_repl), data)
                          out.send(data)
                          print data
                          count = 0
                        #except:
                        #  print "GNS exception:", sys.exc_info()[0]

            else:
                print "\t" "idle", count
                print msg
            if count == max_idling: break

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT  = do_GET
    do_DELETE=do_GET

class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
                           BaseHTTPServer.HTTPServer): pass

if __name__ == '__main__':
    from sys import argv
    if argv[1:] and argv[1] in ('-h', '--help'):
        print argv[0], "[port [allowed_client_name ...]]"
    else:
        if argv[2:]:
            allowed = []
            for name in argv[2:]:
                client = socket.gethostbyname(name)
                allowed.append(client)
                print "Accept: %s (%s)" % (client, name)
            ProxyHandler.allowed_clients = allowed
            del argv[2:]
        else:
            print "Any clients will be served..."
        BaseHTTPServer.test(ProxyHandler, ThreadingHTTPServer)

