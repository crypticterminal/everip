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

sock.connect("/tmp/ever-socket-fca52498ab05b19f7e0069d09d568e7c.sock")

sock.send("hello")

while True:
  datagram = sock.recv(1024)
  p = scapy.IPv6(_pkt=datagram[4:])
  i = p[scapy.ICMPv6EchoRequest]
  sock.send(datagram[:4] + str(ICMPReply(p.dst, p.src, i.id, i.seq, i.data)))
