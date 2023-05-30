# -*- coding: utf-8 -*-
# @Time : 2023/5/30 9:58
# @Author : 89261
# @Email : 892612337@qq.com
# @File : host_scan.py
# @Project : vuln-scan
# @脚本说明 :
import ipaddress
import os
import sys
import threading

from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def host_scan_ping(host):
    platform = sys.platform

    if platform.startswith('win'):
        cmd = f"ping {host} -n 1 -i 1"
    elif platform.startswith('linux'):
        cmd = f"ping {host} -c 1 -t 1"

    try:
        res = os.popen(cmd).read()
    except:
        print("参数错误，请重试！")
    else:
        if '字节=32' in res or 'ttl=64' in res:
            print(f'{host} is alive')


def host_scan_arp(host):
    try:
        pkg = ARP(pdst=f'{host}')
        reply = sr1(pkg, timeout=1, verbose=False)
        res = reply['ARP'].ptype
    except:
        pass
    else:
        print(f'{host} is alive')


def ping_scan(network):
    try:
        network = ipaddress.ip_network(network)

    except ValueError as e:
        print("无效的网段:", e)

    else:
        print('[+] 开始进行主机扫描')
        for ip in network.hosts():
            th = threading.Thread(target=host_scan_ping, args=(str(ip),))
            th.start()
        th.join()
        print('[+] 扫描完成')


def arp_scan(network):
    try:
        network = ipaddress.ip_network(network)

    except ValueError as e:
        print("无效的网段:", e)

    else:
        print('[+] 开始进行主机扫描')
        for ip in network.hosts():
            th = threading.Thread(target=host_scan_arp, args=(str(ip),))
            th.start()
        th.join()
        print('[+] 扫描完成')


if __name__ == '__main__':
    arp_scan('192.168.12.0/24')
