#!/usr/bin/python
#encoding:utf-8

import pexpect
import json
verify_timeout = 3
post_json_list = []
class Connection:
    def __init__(self,ip,auth_queue):
        self.new_state(conn_state)
        self.auth_queue = auth_queue
        self.ip = ip
        self.index = 0
        self.auth = None
        self.child = None


    def new_state(self,newstate):
        self._state = newstate

    def run(self):
        self._state._run(self)

    def exit(self):
        if self.child:
            self.child.close(force=True)

class conn_state:
    @staticmethod
    def _run(conn):
        #print ("conn_state")
        try:
            conn.child = pexpect.spawn("telnet %s" % conn.ip)
            index = conn.child.expect(["sername:","nter:","ccount:","ogin:","eject",pexpect.TIMEOUT,pexpect.EOF],timeout=verify_timeout)
            #print ("conn_state %s:index=%s" % (conn.ip,index))
            if index < 4:
                #print "Got flag %s" % conn.ip
                conn.new_state(user_state)
            else:
                conn.new_state(None)
        except:
            conn.new_state(None)

class user_state:
    @staticmethod
    def _run(conn):
        try:
            conn.auth = conn.auth_queue.pop()
        except:
            conn.new_state(None)
            return

        user = conn.auth[0]
        conn.child.sendline(user)
        index = conn.child.expect([r"[>$~/]","ssword:","sername:","nter:","ccount:","ogin:",pexpect.TIMEOUT,pexpect.EOF],timeout=verify_timeout)
        #print ("user_state %s:%s-%s:index=%s" % (conn.ip,conn.auth[0],conn.auth[1],index))
        if index == 0:
            print ("Got password %s:%s-%s" % (conn.ip,conn.auth[0],""))
            post_json_list_add(conn.ip,conn.auth[0],"")
            conn.new_state(None)
        elif index == 1:
            conn.new_state(passwd_state)
        elif index < 6:
            conn.new_state(user_state)
        else:
            conn.new_state(conn_state)

class passwd_state:
    @staticmethod
    def _run(conn):
        if conn.auth:
            passwd = conn.auth[1]
        else:
            conn.new_state(None)
            return
        conn.child.sendline(passwd)
        index = conn.child.expect([r"[>$~/]","elcome","ername:","nter:","ccount:","ogin:","ssword:",pexpect.TIMEOUT,pexpect.EOF],timeout=verify_timeout)
        print ("passwd_state %s:%s-%s:index=%s" % (conn.ip,conn.auth[0],conn.auth[1],index))        
        if index <= 1:
            print ("Got password %s:%s-%s" % (conn.ip,conn.auth[0],conn.auth[1]))
            post_json_list_add(conn.ip,conn.auth[0],conn.auth[1])
            conn.new_state(None)
        elif index < 5:
            conn.new_state(user_state)
        else:
            conn.new_state(conn_state)

def post_json_list_add(ip,user,auth):
    post_str = {}
    post_str["ip"] = ip
    post_str["user"] = user
    post_str["auth"] = auth
    post_json_list.append(post_str)
