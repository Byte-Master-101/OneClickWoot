# from re import S
from os import system, geteuid
from scapy.layers.dot11 import Dot11Elt, Dot11
# from scapy.packet import Dot11
from scapy.config import conf
from scapy.all import sniff
from socket import if_nameindex
from InquirerPy import prompt
from InquirerPy.enum import INQUIRERPY_FILL_CIRCLE_SEQUENCE
from threading import Thread

interface = None
pointer = INQUIRERPY_FILL_CIRCLE_SEQUENCE
SSIDList = []

def sniffThread():
    sniff(iface=interface, prn=sniffCallback, store=0)

def sniffCallback(packet):
    try:
        DestMAC = packet[0].addr1
        SrcMAC = packet[0].addr2
        BSSID = packet[0].addr3
    except:
        pass
    try:
        SSIDLen = packet[0][Dot11Elt].len
        SSID = packet[0][Dot11Elt].info
    except:
        SSIDLen = 0
        SSID = None

    if SSID == None: return

    # print(SSID)
    global SSIDList
    SSIDList.insert(0, SSID.decode('utf=8'))
    SSIDList = list(set(SSIDList))

    # print(SSID)
    # if packet[0].type == 0:
    #     ST = packet[0][Dot11].subtype
    #     if (str(ST) == 8 and SSID != None and DestMAC.lower() == "ff:ff:ff:ff:ff:ff"):
    #         p = packet[Dot11Elt]
    #         cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
    #         "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

    #         channel = None
    #         crypto = set()

# def init_process():
#     global ssid_list
#     ssid_list = {}
#     global s
#     s = conf.L2socket(iface=newiface)


def doAttack():
    refreshNetworks = True
    while refreshNetworks:
        refresh = "Refresh Networks List"
        back = "Back to Main Menu"
        result = prompt({ "message": "Select WiFi Network:", "type": "list", "choices": [refresh, back] + [f"# {x}" for x in SSIDList], "pointer": pointer})

        refreshNetworks = result[0] == refresh
    
    if result[0] == back: return

    SSID = result[0][2:]
    print(f"Attacking \"{SSID}\"...")

def doCrack():
    back = "Back to Main Menu"
    result = prompt({ "message": "Select Captured Handshake to Crack:", "type": "list", "choices": ["# Network A", back], "pointer": pointer })

def main():
    if geteuid() != 0:
        print("Please run this script as root")
        exit(1)

    interfaces = if_nameindex()
    result = prompt({ "message": "Select WiFi Adapter:", "type": "list", "choices": [f"# {x[1]}" for x in interfaces] + ["Quit"], "pointer": pointer })
    if result[0] == "Quit": exit(0)

    global interface
    interface = result[0][2:]

    print("Turning interface into monitor mode...")
    # system(f"ifconfig {interface} down")
    # system(f"iwconfig {interface} mode monitor")
    # system(f"ifconfig {interface} up")
    print("Interface turned into monitor mode!")

    Thread(target=sniffThread, daemon=True).start()
    # sniff(iface=interface, prn=sniffCallback, store=0)

    while True:
        attack = "Capture Wifi Handshakes"
        crack = "Crack Captured Handshakes"
        result = prompt({ "message": "Select Action:", "type": "list", "choices": [attack, crack, "Quit"], "pointer": pointer })

        if result[0] == attack: doAttack()
        elif result[0] == crack: doCrack()
        else: quit()

if __name__ == "__main__":
    main()
