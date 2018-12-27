#!/usr/bin/python2.7
import sys
import json
import base64
import requests

redis_api = "http://{IP_REDIS_API}:5000/api/0/rpush/elastalert%3aiptables/"
obj = json.loads(sys.stdin.read())
machines = []
ips = []
black_list = ["0.0.0.0", "127.0.0.1", "localhost", "10.33.93.178"]

hosts_map = {}
hosts_map["server-01"] = "server-01.example.com"
hosts_map["server-02"] = "server-02.example.com.br"

for event in obj:
        try:
                ips.append(event['ip'])
                machines.append(event['machine'])

                for ip in ips:
                        for machine in machines:
                                black_list.append(machine)
                                if ip not in black_list and hosts_map[machine] != None:
                                        command = "ansible " + hosts_map[machine] + " -m iptables -a \"chain=INPUT source=" + ip + " jump=DROP\" -s "

                                        headers = {'Content-type': 'application/json'}
                                        payload = '{"values":["' + base64.b64encode(bytes(command)) + '"]}'
                                        print(payload)
                                        print(requests.post(redis_api, data=payload, headers=headers).text)

                                black_list.pop(-1)
        except:
                print("ERROR: " + event)

