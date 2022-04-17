from InquirerPy import prompt
from InquirerPy.enum import INQUIRERPY_FILL_CIRCLE_SEQUENCE

pointer = INQUIRERPY_FILL_CIRCLE_SEQUENCE

def doAttack():
    refreshNetworks = True
    while refreshNetworks:
        refresh = "Refresh Networks List"
        back = "Back to Main Menu"
        result = prompt({ "message": "Select WiFi Network:", "type": "list", "choices": [refresh, "# Network A", "# Network B", back], "pointer": pointer})

        refreshNetworks = result[0] == refresh

def doCrack():
    back = "Back to Main Menu"
    result = prompt({ "message": "Select Captured Handshake to Crack:", "type": "list", "choices": ["# Network A", back], "pointer": pointer })

while True:
    attack = "Capture Wifi Handshakes"
    crack = "Crack Captured Handshakes"
    result = prompt({ "message": "Select Action:", "type": "list", "choices": [attack, crack, "Quit"], "pointer": pointer })

    if result[0] == attack: doAttack()
    elif result[0] == crack: doCrack()
    else: quit()
