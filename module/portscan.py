# -*- coding: utf-8 -*-
# @Time : 2023/5/29 19:58
# @Author : 89261
# @Email : 892612337@qq.com
# @File : portscan.py
# @Project : vuln-scan
# @脚本说明 :
import socket
import threading
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr1
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
active_port_list = []


def scan_port_tcp(host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
        sock.settimeout(1)
        sock.close()
    except Exception as e:
        pass
    else:
        active_port_list.append(port)


def scan_port_syn(host, port):
    try:
        pkg = IP(dst=host) / TCP(dport=port)
        reply = sr1(pkg, timeout=1, verbose=False)
        if reply[TCP].flags == 'SA':
            active_port_list.append(port)
    except Exception as e:
        pass


def full_port_scan(ip):
    active_port_list.clear()

    for port in range(0, 65536):
        th = threading.Thread(target=scan_port_tcp, args=(ip, port))
        th.start()

    th.join()
    active_port_list.sort()

    return active_port_list


def full_port_scan_syn(ip):
    active_port_list.clear()

    for port in range(0, 65536):
        th = threading.Thread(target=scan_port_syn, args=(ip, port))
        th.start()

    th.join()
    active_port_list.sort()

    return active_port_list


def port_scan(ip, port_list):
    active_port_list.clear()

    for port in port_list:
        th = threading.Thread(target=scan_port_tcp, args=(ip, port))
        th.start()

    th.join()
    active_port_list.sort()

    return active_port_list


if __name__ == '__main__':
    print(port_scan('192.168.38.153', [21, 22, 80, 445, 443, 3306, 8080]))
