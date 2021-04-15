import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Target IP / IP range.')

    options = parser.parse_args()
    if not options.target:
        parser.error(
            '[-] Please specify an IP / IP range, use --help for more info.')

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    dst = 'ff:ff:ff:ff:ff:ff'
    broadcast = scapy.Ether(dst=dst)
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_sesult(results_list):
    print('IP\t\t\tMAC Address')
    print('-------------------------------------')

    for client in results_list:
        print(f'{client["ip"]}\t\t{client["mac"]}')


options = get_arguments()

ip = options.target
# ip = "10.0.2.1/24"
# ip = "192.168.10.1/24"

scan_result = scan(ip)
print_sesult(scan_result)
