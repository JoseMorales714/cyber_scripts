import sys
import os

# assists with sending and receiving packets
# scapy is all about network packet manipulation and analysis use
from scapy.all import ICMP, IP, sr1, TCP, sr, UDP

# formatting
from ipaddress import ip_network

# used for parallel processing
from concurrent.futures import ThreadPoolExecutor, as_completed

# print single progress meter on terminal
from threading import Lock

# ensures thread safe printing
# Lock() is used tro create lock objs that are used to sync threads
# to ensure only 1 thread can access pieve of code at a time
# Two States: Locked and unlocked. init state is unlocked
print_lock = Lock()


def ping(host):

    # this sends ICMP packet, get get null or !null response
    # sr1 is send and revieve one packet : sends and waits for response
    # IP() creates IP packet
    # dst=str() sets dest
    # ICMP() creates ICMP packet, ICMP is used for error messages and oeprational information queries link ping
    # timeout for 1, if no response then function will return 'None'
    # verbose set to 0 because no output will be used here for the console
    response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)

    if response is not None:
        print(f"\nFound host ->{host}\n")
        return str(host)
    return None


def ping_sweep(network, netmask):
    live_hosts = []

    # this is for amount of tasks we want to run concurrently, this sets it to current computer cpu threads
    num_threads = os.cpu_count()
    print(f"\nFound num_threads ->{num_threads}\n")

    # hosts is a list of all ip address in that network range
    hosts = list(ip_network(network + '/' + netmask).hosts())
    total_hosts = len(hosts)

    # ops with multithreading
    # Threadpoolexecutor is class from concurrent.futures that is used to create threads
    # Threadpoolexecutor allows to manage worker threads for submitting tasks async
    # with is used to create context for threadpoolexe is active
    # with ensures this call is properlty cleaned up when block exits with exception or without it
    # executor is instance of threadpoolexe that allows to submit tasks to threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:

        # futures submits the tasks to threads whic is a ping here
        # ping is executed on the host
        # future is dictionary and the keys are Future objects representing the tasks
        # and the values are corresponding host addresses
        futures = {executor.submit(ping, host): host for host in hosts}

        # ascompleted() returns iterator that yields Future object in real time
        # enumerate() is used to iterate over Future objects with i as index from starting 1
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]

            # result is the action result, here it is ping
            #  if ping raises exception then future.result() will reraise it
            result = future.result()
            with print_lock:
                print(f"Scanning {i}/{total_hosts}", end="\r")
                if result is not None:
                    print(f"\nHost {host} is online.")
                    live_hosts.append(result)

    return live_hosts

def scan_port(args):
    ip, port=args

    # this sends TCP SYN packet instead of echo requets using ICMP
    # checks if TCP port on host is open
    # this will expect TCP SYN ACK response if the port is open or TCP RST if port closed
    # there are several falgs, S = syn, A = Ack, F = FIN, R = RST etc
    response = sr1(IP(dst=str(ip))/TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response is not None and response[TCP].flags == "SA":
        # SA is SYNACK packet meaning interaction occurred
        return port

    return None

def port_scan(ip, ports):
    open_ports = []
    num_threads = os.cpu_count()
    total_ports = len(ports)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}

        # enumerate adds counter to an ecx or iterable
        # returns adn enumerate obj yielding pairs of an index from start
        # and the tiems from OG iterable
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            result = future.result()
            with print_lock:
                print(f"Scanning {ip}: {i}/{total_ports}", end="\r")
                if result is not None:
                    print(f"\nPort {port} is open on host {ip}")
                    open_ports.append(result)

    return open_ports

# control plane of this program
def get_live_hosts_and_ports(network, netmask):
    live_hosts = ping_sweep(network, netmask)
    host_port_mapping = {}
    ports = range(1,1024)

    for host in live_hosts:
        open_ports = port_scan(host, ports)
        host_port_mapping[host] = open_ports

    return host_port_mapping


##################
##################
######START#######
##################
##################


if __name__ == "__main__":

    #import sys

    network = sys.argv[1]
    netmask = sys.argv[2]

    host_port_mapping = get_live_hosts_and_ports(network, netmask)

    for host, open_ports in host_port_mapping.items():
        print(f"\nHost {host} has the following ports open: {open_ports}")
