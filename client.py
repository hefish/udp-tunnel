#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import hashlib
import getopt
import fcntl
import time
import struct
import socket
import select
import traceback
import signal
import ctypes
import binascii
from Crypto.Cipher import ARC4

SHARED_PASSWORD = hashlib.sha1("keke").hexdigest();
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001

BUFFER_SIZE = 8192
DEBUG = 0
server_ip = ""
server_port = 0
IFACE_IP = "10.2.0.1/24"
MTU = 1500
TIMEOUT = 600


class UDPTunnelClient():

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
        print "Configuring interface %s with ip %s" % (self.tname, ip)
        os.system("ip link set %s ip" % (self.tname))
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))

    def config_routes(self):
        print "Setting up new gateway ..."
        # Look for default route
        routes = os.popen("ip route show").readlines()
        defaults = [x.rstrip() for x in routes if x.startswith("default")]
        if not defaults:
            raise Exception("Default route not found, maybe not connected!")
        self.prev_gateway = defaults[0]
        self.prev_gateway_metric = self.prev_gateway + " metric 2"
        self.new_gateway = "default dev %s metric 1" % (self.tname)
        self.tun_gateway = self.prev_gateway.replace("default", server_ip)
        self.old_dns = file("/etc/resolv.conf", "rb").read()
        os.system("ip route del " + self.prev_gateway)
        os.system("ip route add " + self.prev_gateway_metric)
        os.system("ip route add " + self.tun_gateway)
        os.system("ip route add " + self.new_gateway)
        file("/etc/resolv.conf", "wb").write("nameserver 1.1.1.1\n")

    def restore_routes(self):
        print "Restoring previous gateway ..."
        os.system("ip route del " + self.new_gateway)
        os.system("ip route del " + self.prev_gateway_metric)
        os.system("ip route del " + self.tun_gateway)
        os.system("ip route add " + self.prev_gateway)
        file("/etc/resolv.conf", "wb").write(self.old_dns)


    def run(self):
        global server_ip, server_port
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0))

        self.clients = {}
        self.logged = False
        self.try_logins = 5
        self.log_time = 0

        while True:
            if not self.logged and time.time() - self.log_time > 2.0:
                print "Do login..."
                self.udpfd.sendto("LOGIN:"+ SHARED_PASSWORD + ":" + IFACE_IP.split("/")[0], (server_ip, server_port))
                self.try_logins -= 1
                if self.try_logins == 0:
                    raise Exception("Failed to login. ")
                self.log_time = time.time()

            rset = select.select([self.udpfd, self.tfd], [], [], 1)[0]
            for r in rset:
                if r == self.tfd:
                    if DEBUG:
                        os.write(1, ">")
                    data = os.read(self.tfd, MTU)
                    if DEBUG:
                        os.write(1, "Read from tunnel: %s" % data)

                    data = self.encrypt(data)
                    self.udpfd.sendto(data, (server_ip, server_port))
                elif r == self.udpfd:
                    if DEBUG:
                        os.write(1, "<")

                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if DEBUG:
                        os.write(1, "Read from udp socket(%s): %s" % (src, data))

                    if data.startswith("LOGIN"):
                        if data.endswith("PASSWORD"):
                            self.logged = False
                            print "Need password to login. "
                        elif data.endswith("SUCCESS"):
                            self.logged = True
                            self.try_logins = 5
                            print "Logged in server successfully"

                    else:
                        data = self.decrypt(data)
                        os.write(self.tfd, data)

    def encrypt(self,data):
        encryptor = ARC4.new(self.encrypt_key)
        return encryptor.encrypt(data)

    def decrypt(self,data):
        encryptor = ARC4.new(self.encrypt_key)
        return encryptor.decrypt(data)

def usage(status = 0):
    print "Usage: %s [-s server_ip ] [-p server_port] [-hd] [-l local_ip] [-m password]" % sys.argv[0]
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught ")

if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "s:p:l:r:m:hd")
    for opt, optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-d":
            DEBUG +=1
        elif opt == "-s":
            server_ip = socket.gethostbyname(optarg)
        elif opt == "-p":
            server_port = int(optarg)
        elif opt == "-l":
            IFACE_IP = optarg
        elif opt == "-m":
            SHARED_PASSWORD = hashlib.sha1(optarg).hexdigest()

    tun = UDPTunnelClient()
    tun.create()
    tun.config(IFACE_IP)
    signal.signal(signal.SIGTERM, on_exit)
    tun.config_routes()

    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        tun.restore_routes()
        tun.close()
