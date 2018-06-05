#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import hashlib
import fcntl
import getopt
import time
import struct
import socket
import select
import traceback
import signal
import ctypes
import binascii
from Crypto.Cipher import ARC4

SHARED_PASSWORD = hashlib.sha1("keke").hexdigest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

IFACE_IP = "10.2.0.1/24"
MTU = 1500
TIMEOUT = 600

BUFFER_SIZE=8192
DEBUG = 0
PORT = 7748

class UDPTunnelServer():

    def __init__(self):
        self.encrypt_key = SHARED_PASSWORD

    def create(self):
        try:
            self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            self.tfd = os.open("/dev/tun", os.O_RDWR)

        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
        self.tname = ifs[:16].strip("\x00")

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        print "Configuring interface %s with ip %s " % (self.tname, ip)
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s " % (ip, self.tname))


    def run(self):
        global PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", PORT))

        self.clients = {}
        self.logged = False
        self.try_logins = 5
        self.log_time = 0

        while True:
            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                # 从tunnel和udp socket中获取准备好的fd
                if r == self.tfd:
                    if DEBUG:
                        os.write(1, ">")
                    data = os.read(self.tfd, MTU)

                    src, dst = data[16:20], data[20:24]

                    if DEBUG:
                        os.write(1, "Read from tunnel: %s \n" % data)

                    for key in self.clients:
                        if dst == self.clients[key]['localIPn']:
                            # encrypt data before send to udp socket
                            data = self.encrypt(data)
                            self.udpfd.sendto(data, key)

                    current_time = time.time()
                    for key in self.clients.keys():
                        if current_time - self.clients[key]['aliveTime'] > TIMEOUT:
                            print "Remove timeout client: ", key
                            del self.clients[key]

                elif r == self.udpfd:
                    if DEBUG:
                        os.write(1, "<")
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if DEBUG:
                        os.write(1, "Read from udp tunnel(%s): %s \n" % (src,data))

                    key = src
                    if  key not in self.clients:
                        # new client arrives
                        try:
                            os.write(1, "<"+data.split(":")[1])
                            if data.startswith("LOGIN:") and data.split(":")[1] == SHARED_PASSWORD:
                                local_ip = data.split(":")[2]
                                self.clients[key] = {'aliveTime': time.time(), 'localIPn': socket.inet_aton(local_ip)}
                                print "New client from", src, "request IP", local_ip
                                self.udpfd.sendto("LOGIN:SUCCESS", src)

                        except:
                            print "Need valid password from ", src
                            self.udpfd.sendto("LOGIN:PASSWORD", src)
                    else:
                        ## data arrives
                        # decrypt data before send to tunnel
                        data = self.decrypt(data)
                        os.write(self.tfd, data)
                        self.clients[key]['aliveTime'] = time.time()

    def encrypt(self,data):
        encryptor = ARC4.new(self.encrypt_key)
        return encryptor.encrypt(data)

    def decrypt(self,data):
        encryptor = ARC4.new(self.encrypt_key)
        return encryptor.decrypt(data)


def usage(status = 0):
    print "Usage: %s [-p port] [-l tunnel_ip] [-hd] [-m password]" % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught! ")

if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "p:c:m:hd")
    for opt, optarg in opts[0]:
        if opt == '-h':
            usage()
        elif opt == '-d':
            DEBUG = 1
        elif opt == '-p':
            PORT = int(optarg)
        elif opt == '-l':
            IFACE_IP = optarg
        elif opt == '-m':
            SHARED_PASSWORD = hashlib.sha1(optarg).hexdigest()

    tun = UDPTunnelServer()
    tun.create()
    tun.config(IFACE_IP)
    signal.signal(signal.SIGTERM, on_exit)

    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        tun.close()
