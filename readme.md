#UDPTunnel

####An encrypt tunnel via udp socket.


####usage:
#####server side:

```
# ./server.py -p 7748 -l 10.2.0.1/24 -m mypass 

```
-p port  服务端运行的udp port

-l ip    tunnel的IP

-m mypass  服务端的密码



#####client side:
```
# ./client.py -s vpn.heyu.pw -p 7748 -l 10.2.0.123/24 -m mypass
```

-s hostname  服务端的IP

-p port 服务端的port

-l ip   本地tun设备的IP

-m mypass  服务端的密码


