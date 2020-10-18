import scapy.all as scapy

print("  ___  ______ ______        ______ ______  _____  _____  _____  _____  _____  _____ ______ ")
print(" / _ \ | ___ \| ___ \       | ___ \| ___ \|  _  ||_   _||  ___|/  __ \|_   _||  _  || ___ |")
print("/ /_\ \| |_/ /| |_/ /______ | |_/ /| |_/ /| | | |  | |  | |__  | /  \/  | |  | | | || |_/ /")
print("|  _  ||    / |  __/|______||  __/ |    / | | | |  | |  |  __| | |      | |  | | | ||    / ")
print("| | | || |\ \ | |           | |    | |\ \ \ \_/ /  | |  | |___ | \__/\  | |  \ \_/ /| |\ \ ")
print("\_| |_/\_| \_|\_|           \_|    \_| \_| \___/   \_/  \____/  \____/  \_/   \___/ \_| \_|")
print("-----------------------------------CREATED BY SARVESH--------------------------------------")
print("\n\n")
interface = input("Type the Name Of Your InterFace Name.ex:eth0: ")


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answer_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if response_mac != real_mac:
                print("[+]YOU ARE UNDER ATTACK")

        except IndexError:
            pass


sniff(interface)
