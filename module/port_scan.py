# -*- coding: utf-8 -*-
# @Time : 2023/5/29 19:58
# @Author : 89261
# @Email : 892612337@qq.com
# @File : port_scan.py
# @Project : vuln-scan
# @脚本说明 :
import socket
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# tcp全连接扫描
def scan_port_tcp(host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
        sock.settimeout(1)
        sock.close()
    except Exception as e:
        pass
    else:
        print(f'target port {port} is open')


# 全端口扫描
def full_port_scan(ip):
    for port in range(0, 65536):
        th = threading.Thread(target=scan_port_tcp, args=(ip, port))
        th.start()

    th.join()


# 指定端口扫描
def port_scan(ip, port_list):
    """
    :param ip: ip address
    :param port_list: 端口列表，类型是list
    """

    for port in port_list:
        th = threading.Thread(target=scan_port_tcp, args=(ip, port))
        th.start()

    th.join()


if __name__ == '__main__':
    port_scan('192.168.38.153', [21, 22, 80, 445, 443, 3306, 8080])
