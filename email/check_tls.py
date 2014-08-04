#!/usr/bin/python

import ssl
import socket
import sys
import pprint

def get_response_or_quit(sock, expect="250"):
  buf = sock.recv(1024)
  if buf[:len(expect)] != expect:
    print "[-] Unexpected SMTP response. Expected %s but got \"%s\"" % \
          (expect, buf)
    sys.exit(1)
  return buf

if len(sys.argv) < 2:
  print "Usage: ./check_tls.py <server>"
  sys.exit(-1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((sys.argv[1], 25))

buf = get_response_or_quit(sock, "220")
print "<- %s" % buf.rstrip("\r\n")
sock.send("EHLO starttls-test\r\n")
buf = get_response_or_quit(sock, "250")
print "<- %s" % buf.rstrip("\r\n")

if buf.find("250-STARTTLS\r\n"):
  sock.send("STARTTLS\r\n")
else:
  print "[-] STARTTLS not advertised"
  sys.exit(2)

buf = get_response_or_quit(sock, "220")
print "<- %s" % buf.rstrip("\r\n")

ssock = ssl.wrap_socket(sock, ca_certs="/etc/ssl/certs/ca-certificates.crt", ssl_version=ssl.PROTOCOL_SSLv23, cert_reqs=ssl.CERT_REQUIRED)
ssock.send("EHLO starttls-test\r\n")
buf = get_response_or_quit(ssock, "250")
print "<- %s" % buf.rstrip("\r\n")

pprint.pprint(ssock.getpeercert())
sys.exit(0)
