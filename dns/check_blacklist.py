#!/usr/bin/python

import sys
from pprint import pprint
import dns.message
import dns.query
import signal
import socket
import select
import random
import time

g_maxQueueLen = 10000
g_localResolver = "127.0.0.1"
g_blacklistFile = "blacklists.txt"
# time in seconds, must be type float
g_responseTimeout = 2.0
g_sendDelay = 0.01

g_ip = []
g_blacklist = []
g_query = []
g_message = dns.message.make_query("dummy", "A")

def handleResponse(fd, event, from_addr, wire):
  try:
    r = dns.message.from_wire(wire)
  except:
    sys.stderr.write("invalid response. ip:%s\n" % from_addr)
    return

  msglen = len(wire)
  print "XXX wire:%d \n-----\n%s\n----------\n" % (msglen, r.to_text())
  if r.id >= len(g_query):
    sys.stderr.write("State lookup failed from %s id:%u\n" % (from_addr, r.id))
    return

  (orig_ip, orig_blacklist) = g_query[r.id]
  orig_name = buildQueryName(orig_ip, orig_blacklist)

  if ( r.rcode() is not dns.rcode.NOERROR and
       r.rcode() is not dns.rcode.NXDOMAIN ):
    sys.stderr.write("Blacklist %s returned an error %s\n" % \
                     (orig_blacklist, dns.rcode.to_text(r.rcode())))
    return
  if r.answer:
    try:
      answer = r.find_rrset(r.answer, dns.name.from_text(orig_name),
                            dns.rdataclass.IN, dns.rdatatype.A)
      print "%s@%s:%s" % (orig_ip, orig_blacklist, answer.items[0])
    except:
      sys.stderr.write("expected answer not found %s\n" % orig_name)

def buildQueryName(ip, blacklist):
  tmp = ip.split('.')
  tmp.reverse()
  name = ".".join(tmp) + "." + blacklist
  return name

def queryBlacklist(s, ip, blacklist, id):
  g_message.id = id
  blacklist = blacklist.lower()
  name = buildQueryName(ip, blacklist)
  g_message.question = []
  g_message.question.append(dns.rrset.RRset(dns.name.from_text(name),
                                            dns.rdataclass.IN,
                                            dns.rdatatype.ANY))
  s.sendto(g_message.to_wire(), (g_localResolver, 53))

def resolver():
  s = socket.socket(dns.inet.AF_INET, socket.SOCK_DGRAM)
  s.setblocking(0)
  s.bind(("0.0.0.0", 0))

  read_only = select.POLLIN|select.POLLERR
  read_write = read_only|select.POLLOUT
  event_mask = read_write

  p = select.poll()
  p.register(s, event_mask)

  timer = 0
  now = 0

  while True:

    # exit program after waiting for results
    if timer:
      now = time.time()
      if now - timer > g_responseTimeout:
        return

    event_list = p.poll(1000)
    for (fd, event) in event_list:

      # read
      if event & select.POLLIN:
        try:
          (wire, from_addr) = s.recvfrom(65536)
        except:
          raise
        addr = from_addr[0]
        handleResponse(fd, event, addr, wire)

      # write
      elif event & select.POLLOUT:
        if g_ip:
          ip = g_ip.pop()
          if ip:
            for blacklist in g_blacklist:
              id = len(g_query)
              g_query.append([ip, blacklist])
              queryBlacklist(s, ip, blacklist, id)
              time.sleep(g_sendDelay)

        # nothing left to write, tell scheduler to go readonly
        else:
          now = time.time()
          timer = now
          p.modify(fd, read_only)


      if event & select.POLLERR:
        sys.stderr.write("poll error: flags 0x%x\n" % event)

def kill_proc(signal, frame):
  sys.exit(0)


signal.signal(signal.SIGINT, kill_proc)

fd = open(g_blacklistFile, 'r')
for line in fd:
  blacklist = line.rstrip()
  g_blacklist.append(blacklist)

for line in sys.stdin:
  ip = line.rstrip()
  ip = ip.lower().rstrip(".");
  g_ip.append(ip)

resolver()

