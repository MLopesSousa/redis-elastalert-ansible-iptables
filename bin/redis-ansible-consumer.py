import redis
import os
import json
import base64

import datetime
import time

import re

redis = redis.Redis(host='localhost', port=6379, db=0)
regex = "^ansible\s[a-zA-Z0-9-._]*\s-m\siptables\s-a\s\"chain=INPUT\ssource=(?:[0-9]{1,3}\.){3}[0-9]{1,3}\sjump=DROP\"\s-s$"

while True:
        val = redis.brpop('elastalert:iptables', timeout=0)
        command = str.strip(base64.b64decode(val[1]))


        if  re.match(regex, command):
                with open("/tmp/redis-ansible-consumer.log", "a") as myfile:
                        myfile.write(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + " [INFO] " + command + "\n")
                os.system(base64.b64decode(val[1]))
        else:
                with open("/tmp/redis-ansible-consumer.log", "a") as myfile:
                        myfile.write(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + " [ERROR] " + command + "regex dont match\n")
