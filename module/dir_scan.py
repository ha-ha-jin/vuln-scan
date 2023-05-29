# -*- coding: utf-8 -*-
# @Time : 2023/5/29 19:38
# @Author : 程进舟
# @Email : 2891889980@qq.com
# @File : dir_scan.py.py
# @Project : pythonProject
# @脚本说明 :
import requests,threading

url_code_list={}

print("cjznb")

def readuri(domain,file):
    with open(file,'r') as f:
        uris=f.readlines()

    threads=[]
    for uri in uris:
        th=threading.Thread(target=joint,args=(uri,domain))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    return url_code_list

def joint(uri,domain):
    if domain.endswith('/'):
        url=domain[0:-1]+uri.strip()
    else:
        url=domain+uri.strip()

    try:
        res=requests.get(url=url)
    except:
        pass
    else:
        url_code_list[url]=res.status_code

if __name__=='__main__':
    print(readuri(domain='http://www.baidu.com/',file='DIR.txt'))
