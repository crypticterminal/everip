# -*- coding: utf-8 -*-
import socket
import os, os.path

from scapy import all as scapy

def ICMPReply(srcaddr, dstaddr, ident, seq, payload):
  ip = scapy.IPv6
  icmp = scapy.ICMPv6EchoReply
  packet = (ip(src=srcaddr, dst=dstaddr) / icmp(id=ident, seq=seq) / payload)
  return packet

path_recv_sock = "/tmp/recv.sock"

if os.path.exists(path_recv_sock):
  os.remove(path_recv_sock)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.bind( path_recv_sock )

sock.connect("/tmp/ever-socket-fc52d8e963d7a04923a47cdbe684d2ae.sock")

sock.send("hello")

while True:
  try:
    datagram = sock.recv(1024)
    p = scapy.IPv6(_pkt=datagram[4:])
    i = p[scapy.ICMPv6EchoRequest]
    sock.send(datagram[:4] + str(ICMPReply(p.dst, p.src, i.id, i.seq, i.data)))
  except KeyboardInterrupt:
    break
  except:
    continue
