import argparse
import socks
from argparse import ArgumentParser
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import *

#proxies = {
#    'http': 'socks5://127.0.0.1:9150',
#    'https': 'socks5://127.0.0.1:9150'
#}

# tor
host = "127.0.0.1"
tor_port = 9150


def print_ports(port, state):
    print("%s -> %s" % (port, state))


def ip_range(input_string):
    octets = input_string.split('.')
    chunks = [list(octet.split('-')) for octet in octets]
    ranges = [range(int(c[0]), int(c[1]) + 1) if len(c) == 2 else c for c in chunks]
    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))


# tor scan
def tor_scan(target, ports, timeout):
    print("TOR | %s" % target)
    for port in ports:
        try:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9150, True)
            socket.socket = socks.socksocket()
            socket.socket.settimeout(timeout)
            # print(socket.socket)
            socket.socket.connect((target, port))
            print_ports(port, "Open")

        except:
            print_ports(port, "Closed")
    socket.socket.close()


# syn scan
def syn_scan(target, ports, timeout):
    print("SYN | %s" % target)
    for port in ports:
        pkt = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
        if pkt:
            # print(pkt.summary())
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:
                    print_ports(port, "Closed")
                elif pkt[TCP].flags == 0x12:
                    print_ports(port, "Open")
                else:
                    print_ports(port, "TCP packet resp / filtered")
            elif pkt.haslayer(ICMP):
                print_ports(port, "ICMP resp / Filtered")
            else:
                print_ports(port, "Unknown resp")
                print(pkt.summary())
        else:
            print_ports(port, "Filtered")


# fin scan
def fin_scan(target, ports, timeout):
    print("FIN | %s" % target)
    for port in ports:
        pkt = sr1(IP(dst=target) / TCP(dport=port, flags="F"), timeout=timeout, verbose=0)
        if pkt:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:
                    print_ports(port, "Closed")
                elif pkt.haslayer(ICMP):
                    if int(pkt[ICMP].type) == 3 and int(pkt[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                        print_ports(port, "Filtered")
                    else:
                        print_ports(port, "ICMP resp / Filtered")
                else:
                    print_ports(port, "TCP packet resp / Filtered")
            else:
                print_ports(port, "Unknown resp")
                print(pkt.summary())
        else:
            print_ports(port, "Filtered")


def main():
    parser: ArgumentParser = argparse.ArgumentParser("Port scanner using Scapy")
    parser.add_argument("-t", "--target", help="Target IP", required=True)
    parser.add_argument("-w", "--wait", help="Time wait send")
    parser.add_argument("-r", "--tor", help="Tor proxy", type=bool, nargs='?', const=True, default=False)
    parser.add_argument('-p', '--ports', nargs="+", help='Ports [[?], ?]', required=True)
    parser.add_argument("-s", "--scan", help="Scan type syn/fin/tor", required=True)
    argsParse = parser.parse_args()

    target = argsParse.target
    scan = argsParse.scan.lower()
    if argsParse.ports:
        try:
            beginPort = int(argsParse.ports[0])
            if len(argsParse.ports) > 1:
                endPort = int(argsParse.ports[1])
                assert 0 < beginPort <= endPort and endPort > 0
            else:
                endPort = beginPort
            ports = range(beginPort, endPort + 1)
        except AssertionError:
            print("Port range is invalid - startPort must be <= endPort, both of which > 0")
            sys.exit()
    else:
        # default port range
        ports = range(1, 1024)

    if argsParse.wait:
        timeout = int(argsParse.wait)
    else:
        timeout = 1

    if scan == "syn" or scan == "s":
        for address in ip_range(target):
            syn_scan(address, ports, timeout)
    elif scan == "fin" or scan == "f":
        for address in ip_range(target):
            fin_scan(address, ports, timeout)
    elif scan == "tor" or scan == "r":
        for address in ip_range(target):
            tor_scan(address, ports, timeout)
    else:
        print("Scan type not supported")


if __name__ == '__main__':
    main()
