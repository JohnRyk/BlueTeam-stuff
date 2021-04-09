#!/usr/bin/env python3
# coding=utf-8

from termcolor import colored
import validators
import ipaddress
import argparse
import requests
import socket
import json
import time
import sys

class queryAPI:

    tb_api_key = ""     # <- Your api key
    #vt_api_key = ""

    def querySB(self,ip):
        # query ip.sb
        api_1 = "https://api.ip.sb/geoip/"  
        url = api_1 + ip
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"
        headers = {\
            'authority': 'api.ip.sb',\
            'referer': 'https://ip.sb/',\
            'user-agent': ua\
        }
        try:
            response = requests.get(headers = headers, url = url)
        except Exception as e:
            print(e)
            return "[-] HTTP request error !"
        if response.status_code == 200:
            return response.text.strip("\n")
        else:
            print("[-] Query ip.sb error !")

    def queryVT(self,ip):
        # query virustotal
        api_key = self.vt_api_key
        query_type = ""
        pass

    def queryTB(self,ip):
        # query threatbook
        # reference: https://x.threatbook.cn/api_docs#/ip/query
        api_key = self.tb_api_key
        resource = ip
        url = "https://api.threatbook.cn/v3/scene/ip_reputation"
        query = {
            "apikey": api_key,
            "resource": resource
        }
        try: 
            response = requests.request("GET", url, params=query)
        except Exception as e:
            print(e)
            return "[-] HTTP request error !"
        if response.status_code == 200:
            return response.text.strip("\n")
        else:
            print("[-] Query ThreatBook error !")
        

def getData(target, query_type):
    query_api = queryAPI()
    data = {}
    if check_input(target) == 'ip':
        ip = target.strip('\n')
    elif check_input(target) == 'dn':
        ip = socket.gethostbyname(target)
    else:
        print("[-] Invalid argument")
        sys.exit(0)
    if check_private(ip):
        data[ip] = '{\"ip\":\"Private IP\"}'
    elif query_type == None:
        get_data = query_api.querySB(ip)
        time.sleep(0.1)     # delay
        data[ip] = get_data
    elif query_type == "tb":
        get_data = query_api.queryTB(ip)
        time.sleep(0.1)     # delay
        data[ip] = get_data
    elif query_type == "vt":
        pass
    return data


def check_private(ip):
    ip_result = ipaddress.ip_address(ip).is_private
    return ip_result

def check_input(user_input):
    if validators.ip_address.ipv4(user_input) or validators.ip_address.ipv6(user_input):
        return "ip"
    elif validators.domain(user_input):
        return "dn"


def readFromFile(file_path, query_type): 
    all_targets = []
    all_targets_data = {}
    # read all targets from file
    with open(file_path,'r') as f:
        all_targets = f.readlines()
    for target in all_targets:
        target = target.strip("\n")
        all_targets_data[target] = getData(target,query_type)[target]
    return all_targets_data


def banner():
    banner = \
"""

██╗██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██║██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
██║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
                                                                               

"""
    print(banner)
    


def parseArg():
    parser = argparse.ArgumentParser(description='Quick IP Analysis Tool\nAuthor: JRZ')
    parser.add_argument('-t','--target',help="Target supports IP or Domain Name")
    parser.add_argument('-f','--filepath',help="Read IPs from specify file path")
    parser.add_argument('-p','--parsefile',help="Parse JSON file data")
    parser.add_argument('-q', '--query', help="Online intelligence api [tb]")
    args = parser.parse_args()
    return args


def example():
    print("Example:\n\
        \tip_analyzer -t 1.1.1.1\n\
        \tip_analyzer -t 1.1.1.1 -q tb\n\
        \tip_analyzer -t www.abc.xyz\n\
        \tip_analyzer -t www.abc.xyz -q tb\n\
        \tip_analyzer -f targets.txt\n\
        \tip_analyzer -f targets.txt -q tb\n\
        \tip_analyzer -p filename\n\
        \tip_analyzer -p filename -q tb\n"\
    )


def saveToFile(name,data,query_type):
    if query_type == None:
        query_type = "sb"
    #date = time.strftime("%Y-%m-%d_%H%M%S",time.localtime())
    date = time.strftime("%Y-%m-%d_%H%M",time.localtime())
    temp_filename = "%s_%s_%s" % (name,date,query_type)
    try:
        #print(data)
        with open(temp_filename,"w") as f:
            f.write(json.dumps(data))
    except Exception as e:
        print(e)
        return
    print("[+] Result save to file   -->   %s" % temp_filename)
    return temp_filename


def parseJSON(file_path, query_type):
    # Parse json and format output
    text = ""
    json_data = ""
    with open(file_path,'r') as f:
        text = f.read()
        json_data = json.loads(text)
    if query_type == None:  # parse ip.sb query result json
        for ip,ip_data in json_data.items():
            print('\n'+'-' * 16 + "\n%s\t|\n" % ip + '-' * 80)
            ip_data = json.loads(ip_data)
            for field,value in ip_data.items():
                if field == "ip":
                    print("%20s %59s" % (field,colored(value,"blue")))
                    continue
                if field == "country":
                    print("%20s %59s" % (field,colored(value,"red")))
                    continue
                if field == "isp":
                    print("%20s %59s" % (field,colored(value,"yellow")))
                    continue
                if field == "longitude":
                    print("%20s %59s" % (field,colored(value,"green")))
                    continue
                if field == "latitude":
                    print("%20s %59s" % (field,colored(value,"green")))
                    continue
                else:
                    print("%20s %50s" % (field,value))
    elif query_type == "tb": # parse threatbook query result json
        for ip,ip_data in json_data.items():
            print('\n'+'-' * 16 + "\n%s\t|\n" % ip + '-' * 80)
            try:
                ip_data = json.loads(ip_data)
                if ip_data['data'][ip]['severity'] == 'info':
                    print("%20s %59s" % ("severity", colored(ip_data['data'][ip]['severity'],"green")))
                else:
                    print("%20s %59s" % ("severity", colored(ip_data['data'][ip]['severity'],"red")))
                    print("%20s %59s" % ("tags_classes", colored(ip_data['data'][ip]['tags_classes'],"blue")))
                print("%20s %59s" % ("judgments", colored(ip_data['data'][ip]['judgments'],"yellow")))
                print("%20s %50s" % ("country", ip_data['data'][ip]['basic']['location']['country'] ))
                print("%20s %50s" % ("province",ip_data['data'][ip]['basic']['location']['province'] ))
                print("%20s %50s" % ("city",ip_data['data'][ip]['basic']['location']['city'] ))
                if ip_data['data'][ip]['is_malicious']:
                    print("%20s %59s" % ("is_malicious", colored(ip_data['data'][ip]['is_malicious'],"red")))
                else:
                    print("%20s %59s" % ("is_malicious", colored(ip_data['data'][ip]['is_malicious'],"green")))
                print("%20s %59s" % ("confidence_level",  colored(ip_data['data'][ip]['confidence_level'],"blue")))
            except Exception as e:
                for field,value in ip_data.items():
                    if field == "ip":
                        print("%20s %59s" % (field,colored(value,"blue")))
                        continue
        pass


if __name__ == '__main__':
    if len(sys.argv) == 1:
        banner()
        example()
        sys.exit(0)

    args = parseArg()

    target_data={}
    all_targets_data = {}

    target = args.target
    query_type = args.query
   
    if args.target:
        # Single query
        target_data = getData(target,query_type)
        filepath = saveToFile(target,target_data,query_type)
        parseJSON(filepath,query_type)
    if args.filepath:
        # Batch query
        filepath = args.filepath
        all_targets_data = readFromFile(filepath, query_type)
        saveToFile(filepath.split("/")[-1],all_targets_data, query_type)
    if args.parsefile:
        # Parse data
        filepath = args.parsefile
        parseJSON(filepath,query_type)






