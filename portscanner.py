#input is done
import argparse #taking cmd line input
import socket
from socket import *
from threading import *

screenlock = Semaphore(value=1)

def portscan(tgthost,tgtport):
    try:
        tgtIP = gethostbyname(tgthost) #eturns IPV4 adress
    except:
        print("[-] Cannot resolve host : Unknown host :" + tgthost)
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print("\n[+] Scan results for :" + tgtName[0])
    except:
        print("\n[+] Scan results for :" + tgtIP)
    
    setdefaulttimeout(2)

    for port in tgtport:
        print("[+] Scanning port " + port )
        connScan(tgthost,int(port))

    
def connScan(tgthost,tgtport):
    try:
        connSkt=socket(AF_INET,SOCK_STREAM)
        connSkt.connect((tgthost,tgtport))
        connSkt.send(b'wssup\r\n')
        results = connSkt.recv(100)
        screenlock.acquire()
        print("[+] "+ str(tgtport) + " is open")
        print("[+] " + str(results))
        
    except:
        screenlock.acquire()
        print("[-] Connection closed " + str(tgtport))
    finally:
        screenlock.release()
        connSkt.close()


def main():
    parser = argparse.ArgumentParser(description="This is a port scanner")

    parser.add_argument("-H" ,required=True,dest="tgthost", help="specify target host")
    parser.add_argument("-p" ,required=True,dest="tgetport", help="specify target port")
    args = parser.parse_args()

    tgthost=args.tgthost
    tgtport=str(args.tgetport).split(",")

    portscan(tgthost,tgtport)

if __name__ == "__main__":
    main()

