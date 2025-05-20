import sys
import argparse
import os
import time
import logging
from datetime import datetime

SDE = os.environ.get("SDE", "/home/andres/Documentos/maestria/goose/sde")
BF_RUNTIME_LIB = SDE + "/lib/python3.5/site-packages/tofino/"
# set our lib path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "./", BF_RUNTIME_LIB))


import grpc
import bfrt_grpc.client as gc
import time
import socket
import json
from datetime import datetime
import netaddr
import socket
import pandas as pd

dat = []
times = []
ports_rqst = {}
ports_rply = {}

recv_flag_rqst = []
recv_flag_rply = []

RQST_THRESHOLD = 5
RPLY_THRESHOLD = 2

atk_port = 1

date_log = datetime.now().strftime("%d-%m-%H-%S")
name_log_file = f"logs/controller-{date_log}.log"

logging.basicConfig(
    filename=name_log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def write_log(message):
    logging.info(message)
    
def get_local_ip():
    try:
        # Get the local hostname
        hostname = socket.gethostname()

        # Get the local IP address using the hostname
        local_ip = socket.gethostbyname(hostname)

        return local_ip
    except socket.error:
        return "Unable to get local IP address"


def decimal_to_ip(decimal):
    # Convert decimal to binary and strip the '0b' prefix
    binary = bin(decimal)[2:]
    # Pad the binary representation to 32 bits
    binary = binary.zfill(32)

    # Split the binary string into four octets
    octets = [binary[i:i+8] for i in range(0, 32, 8)]

    # Convert each octet from binary to decimal and join them with periods
    ip_address = '.'.join(str(int(octet, 2)) for octet in octets)

    return ip_address

def get_match_keys(key_names, rule):

        _key = []
        for key_name, key_param in zip(key_names, rule):
            if type(key_param) != tuple:
                key_param = (key_param,)
            _key.append((key_name,) + key_param)

        return _key

def get_action_values(rule, action_param_names):
        _value = []
        for value_name, value_param in zip(action_param_names, rule):
            _value.append((value_name, value_param))
        return _value

def add_ternary_rules(table_name, key_names, rules,
                          action_param_names, action):
        keys = []
        values = []

        key_values = [x[0] for x in rules]
        action_values = [x[1] for x in rules]

        for rule in key_values:
            keys.append(get_match_keys(key_names, rule))

        for value in action_values:
            values.append(get_action_values(value, action_param_names))

        


        for key, value in zip(keys, values):
            entry_add(
                table_name, key, value, action)

        #return keys, values

def entry_add(table_name, keys=[], data=[], action_name=None):
        table = bfrt_info.table_get(table_name)
        _keys = table.make_key([gc.KeyTuple(*k) for k in keys])
        _data = table.make_data(
            [gc.DataTuple(*d) for d in data], action_name)

        table.entry_add(
            target,
            [_keys],
            [_data]
        )


def rule_update(recv_ip1, recv_ip2, atk_port):

    print("NEW RULE")

    key_names = [
        'hdr.ethernet.dst_addr', 
        'hdr.ipv4.dst_addr',
        'ig_intr_md.ingress_port']

    rules = [
        [((0, 0),
            (recv_ip1, 4294967295), #IP
            (atk_port, 511)),
            ()],
        [((0, 0),
            (recv_ip2, 4294967295),
            (atk_port, 511)),
            ()],
            ]

    add_ternary_rules("l2_broadcast_table", key_names, rules, [], "drop")


def waitReport():

    nbRec=0
    #previousReportTime=datetime.now()

    learn_filter1 = bfrt_info.learn_get("digest_a")
    learn_filter2 = bfrt_info.learn_get("digest_b")
    table = bfrt_info.table_get("l2_broadcast_table")
    
    print("Waiting for Digest packet")

    ts = datetime.now()
    print(ts)

    while 1:
        digest = interface.digest_get(10000)  # Wait for one Digest
        digest_number = str(digest.data).count("field_id")
        data = str(digest.data)
        
        print(digest_number)
        print(digest)
        
        ts = datetime.now()

        nbRec = nbRec+1
        print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nRec : ", nbRec, "       |       ", ts)

        if(digest_number == 4):
            data_list1 = learn_filter1.make_data_list(digest)
            data_dict1 = data_list1[0].to_dict()
            print(type(data_dict1))
            print(data_dict1)
            index_NUM = data_dict1["register_index"]
            diff_st  = data_dict1["diff_st"]
            diff_sq  = data_dict1["diff_sq"]
            diff_port  = data_dict1["diff_port"]
            ingress_timestamp_ns  = data_dict1["ingress_timestamp_ns"]
            egress_timestamp_ns  = data_dict1["egress_timestamp_ns"]

            print("------------------")
            print("INDEX:", index_NUM)
            print("DIFF_ST:", diff_st)
            print("DIFF_SQ:", diff_sq)
            print("DIFF_PORT:", diff_port)
            print("INGRESS_TIME:", ingress_timestamp_ns)
            print("EGRESS_TIME:", egress_timestamp_ns)            
            print("------------------")
            mensaje = f"INDEX:{index_NUM}, DIFF_ST:{diff_st}, DIFF_SQ:{diff_sq}, DIFF_PORT:{diff_port}"
            latencia = egress_timestamp_ns - ingress_timestamp_ns
            print("LATENCIA:", latencia)
            write_log(f"LATENCIA: {latencia}")
            write_log(mensaje)

        elif(digest_number == 5):
            data_list2 = learn_filter2.make_data_list(digest)
            data_dict2 = data_list2[0].to_dict()
            #print(type(data_dict2))
            #print(data_dict2)
            index_NUM = data_dict2["register_index"]
            diff_st  = data_dict2["diff_st"]
            diff_sq  = data_dict2["diff_sq"]
            diff_port  = data_dict2["diff_port"]
            flag  = data_dict2["flag"]
            ingress_timestamp_ns  = data_dict1["ingress_timestamp_ns"]
            egress_timestamp_ns  = data_dict1["egress_timestamp_ns"]
            print("------------------")
            print("INDEX    :     ", index_NUM)
            print("DIFF_ST  :        ", diff_st)
            print("DIFF_SQ  :        ", diff_sq)
            print("DIFF_PORT:        ", diff_port)
            print("FLAG     :        ", flag)
            print("INGRESS_TIME:", ingress_timestamp_ns)
            print("EGRESS_TIME:", egress_timestamp_ns)            
            print("------------------")

            mensaje = f"INDEX:{index_NUM}, DIFF_ST:{diff_st}, DIFF_SQ:{diff_sq}, DIFF_PORT:{diff_port}, FLAG:{flag}"
            write_log(mensaje)
            latencia = egress_timestamp_ns - ingress_timestamp_ns
            print("LATENCIA:", latencia)
            write_log(f"LATENCIA: {latencia}")            

        else:
            if ((digest_number % 4) == 0):
                print("*** +4 DIGEST +4 ***")
                data_list1 = learn_filter1.make_data_list(digest)
                data_dict1 = data_list1[0].to_dict()
                for i in range(0, len(data_list1)):
                    index_NUM = data_dict1["register_index"]
                    diff_st  = data_dict1["diff_st"]
                    diff_sq  = data_dict1["diff_sq"]
                    diff_port  = data_dict1["diff_port"]
                    flag  = data_dict1["flag"]
                    print("------------------")
                    print("INDEX    :     ", index_NUM)
                    print("DIFF_ST  :        ", diff_st)
                    print("DIFF_SQ  :        ", diff_sq)
                    print("DIFF_PORT:        ", diff_port)
                    print("FLAG     :        ", flag)
                    print("------------------")
                    nbRec = nbRec+1
                print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\nRec : ",nbRec)
                
                mensaje = f"INDEX:{index_NUM}, DIFF_ST:{diff_st}, DIFF_SQ:{diff_sq}, DIFF_PORT:{diff_port}, FLAG:{flag}"
                write_log(mensaje)

            elif(digest_number % 5):
                print("*** +5 DIGEST +5 ***")
                data_list2 = learn_filter2.make_data_list(digest)
                data_dict2 = data_list2[0].to_dict()
                for i in range(0, len(data_list2)):
                    index_NUM = data_dict2["register_index"]
                    diff_st  = data_dict2["diff_st"]
                    diff_sq  = data_dict2["diff_sq"]
                    #diff_port  = data_dict2["diff_port"]
                    #flag  = data_dict2["flag"]
                    print("------------------")
                    print("INDEX    :     ", index_NUM)
                    print("DIFF_ST  :        ", diff_st)
                    print("DIFF_SQ  :        ", diff_sq)
                    print("DIFF_PORT:        ", diff_port)
                    print("FLAG     :        ", flag)
                    print("------------------")
                    nbRec = nbRec+1
                print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\nRec : ",nbRec)
                
                mensaje = f"INDEX:{index_NUM}, DIFF_ST:{diff_st}, DIFF_SQ:{diff_sq}, DIFF_PORT:{diff_port}, FLAG:{flag}"
                write_log(mensaje)
               
            else:
                print(digest_number)
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                print("!!!!!!! DIGEST ALERT !!!!!!!")
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        #print("RQST: ---> ", ports_rqst, "--->", type(ports_rqst))
        #print("RPLY: ---> ", ports_rply, "--->", type(ports_rply))
 
if __name__ == "__main__":

    addressCGClassifier = "127.0.0.1"
    portCGClassifier = 5000
    server_port = 1  # P4 port associated the logical switch port where the server traffic is coming
    client_port = 0   # P4 port associated the logical switch port where the client traffic is sent out
    digest_type = 1
    src_IPadd = get_local_ip()  # Local IP Address
    print("Local IP address:", src_IPadd)


    #initConnexionCGClassifier(addressCGClassifier, portCGClassifier)

    recv_mIndex = 100
    client_id = 0
    device_id = 0
    p4_name = "goose_mitigation"
    grpc_addr = '172.21.30.195:50052'
    ## Set interface
    interface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=0, notifications=None, timeout=1, num_tries=5, perform_subscribe=True)
    # Get bfrt_info and set it as part of the test
    bfrt_info = interface.bfrt_info_get(p4_name)
    interface.bind_pipeline_config(p4_name)
    ##Connection to device and to pipe
    target = gc.Target(device_id, pipe_id=0xffff)

    #configureP4switch(target, bfrt_info, server_port, client_port, src_IPadd, digest_type)

    waitReport()
