import subprocess
import argparse
import re


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Interface to change its MAC address\neg. -i eth0')
    parser.add_argument('-m', '--mac', dest='new_mac',
                        help='New MAC address')
    options = parser.parse_args()
    if not options.interface:
        parser.error(
            '[-] Please specify an interface, use --help for more info.')
    elif not options.new_mac:
        parser.error('[-] Please specify a new mac, use --help for more info.')
    return options


def change_mac(interface, new_mac):
    print(f'[+] Changing MAC address for {interface} to {new_mac}')

    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])
    subprocess.call(['ifconfig'])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(
        ['ifconfig', interface]).decode()

    mac_address_search_result = re.search(r'(\w{2}:){5}\w{2}', ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        return '[-] Could not read MAC address.'


options = get_arguments()
current_mac = get_current_mac(options.interface)
print(f'Current MAC = {current_mac}')


change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)

if current_mac == options.new_mac:
    print(f'[+] MAC address was successfully changed to {current_mac}')
else:
    print('[-] MAC address did not get changed')

# print(f'Current MAC = {current_mac}')
# print(options.new_mac)
