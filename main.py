from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.sendrecv import send, sendp, sr, srloop, sr1, sniff
from scapy.utils import wrpcap


def ping(my_adresse:str, adresse: str, message:str = "This is a seizure!", counter:int = 10) -> None:

    # creating package
    ip = IP(src=my_adresse, dst=adresse)
    packet = (ip / ICMP()/message)

    send(packet, count=counter)


def get_my_adresse() -> str:

    #getting adresse to variable and return
    ip = get_if_addr(conf.iface)
    return ip

def port_scan() -> None:

    ans=sr(IP(dst="83.10.56.219")/UDP(dport=(1,1024)))
    ans.nsummary()

def capturePacket(counter:int=5)->None:

    # Setup sniff
    x = sniff(iface="wlan0", count=counter)
    x.show()
    wrpcap('filename.pcap', x, append=True)


n = 1

while n != 0:
    print("""╔╗ ┌─┐┌┬┐┌┬┐┌─┐┬─┐  ┬ ┬┬┬─┐┌─┐┌─┐┬ ┬┌─┐┬─┐┬┌─
╠╩╗├┤  │  │ ├┤ ├┬┘  ││││├┬┘├┤ └─┐├─┤├─┤├┬┘├┴┐
╚═╝└─┘ ┴  ┴ └─┘┴└─  └┴┘┴┴└─└─┘└─┘┴ ┴┴ ┴┴└─┴ ┴""")
    print("What do you want to do? \nFor send packet enter: 1 \nFor scan enter: 2")
    n = int(input("Choice: "))
    if n == 1:
        adresse = str(input("Enter the victim's address: "))
        message = str(input("Write a message! "))
        counter = int(input("How much? "))
        ping(get_my_adresse(), adresse, message, counter)
    elif n == 2:
        #protocol = str(input("Enter the protocol name: "))
        counter = int(input("How much? "))
        capturePacket(counter)
    else:
        break



