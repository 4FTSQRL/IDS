"""
	Description Basic IDS/IPS Script for Linux System
	Authors: 4FTSQRL and KryptonPhantom
"""

#!/usr/bin/env python

# Import Statements
import sys,subprocess,datetime,time
import re
from scapy.all import *


# Start wlan0
for char in ("Killing any interferring systems..."):
	print(char, end='',flush=True)
	time.sleep(0.05)
	
subprocess.run("sudo airmon-ng check kill", shell=True, executable="/bin/bash")

for char in ("Putting adapter into monitor mode..."):
	print(char, end='',flush=True)
	time.sleep(0.05)

subprocess.run("sudo airmon-ng start wlan0", shell=True, executable="/bin/bash")

# Get the BSSID from the user.
#for char in (f"Enter a BSSID to protect: "):
	#print(char,end='',flush=True)
	#time.sleep(0.05)
#bssid=input()

# Get the channel from the user.
for char in ("Enter the channel that corresponds with the BSSID: "):
	print(char,end='',flush=True)
	time.sleep(0.05)
channel=input()

# Change Channel
for char in ("Changing channel..."):
	print(char,end='',flush=True)
	time.sleep(0.05)
changeChannel="sudo iwconfig wlan0 channel "+channel
subprocess.run(changeChannel, shell=True, executable="/bin/bash")

# Get the whitelist
for char in ("\nEnter the path to your whitelist text file: "):
	print(char,end='',flush=True)
	time.sleep(0.05)
whitelist=input()

# Get the BSSIDs
with open(whitelist, 'r') as file:
	data = file.read()
	

	bssidList = re.findall(r'\b\w+:\b\w+:\b\w+:\b\w+:\b\w+:\b\w+',data)
	whitelistFull = data.split()
	# Make all BSSIDs lowercase
	i=0
	for value in whitelistFull:
		if re.search(r'\b\w+:\b\w+:\b\w+:\b\w+:\b\w+:\b\w+',value): 
			whitelistFull[i]=value.lower()
		i+=1
	
# Convert bssidList to lowercase
bssidList = [value.lower() for value in bssidList]

# Packet Counters and Timer
beaconCounter = 0
deauthCounter = 0
disasCounter = 0
authCounter = 0
x = time.time()
y=time.time()

# Beacon attack counter
beaconFloodCounter =0
# Process the packet with a fuction to search for attacks
def detect_attacks(pkt):
	#Time stuff
	global x
	global beaconCounter
	global deauthCounter
	global disasCounter
	global authCounter
	global beaconFloodCounter
	global y
	global bssidList
	global whitelistFull
	
	# Time Difference
	timeDiff =  (time.time() - x)


	if timeDiff >= 3:
		beaconCounter=0
		deauthCounter=0
		disasCounter=0
		authCounter=0
		x=time.time()
		
	# Second Time DIff
	timeDiffy = (time.time() - y)
	if timeDiffy >= 15:
		y=time.time()
		for char in ("\nScanning...\n\n"):
			print(char,end='',flush=True)
			time.sleep(0.08)
	# Look for deauth layer
	if pkt.haslayer(Dot11Deauth) and pkt.addr1.casefold() in bssidList:
		deauthCounter+=1
		if deauthCounter >= 20:
			# Print alert
			print(f"{str(datetime.today())} Deauthentication Attack in progress from {str(pkt.addr2).swapcase()}")
			deauthCounter=0
	# Look for dissossication layer
	if pkt.haslayer(Dot11Disas) and pkt.addr1.casefold() in bssidList:
		disasCounter+=1
		if disasCounter >= 20:
			# Print alert
			print(f"{str(datetime.today())} Deauthentication Attack in progress from {str(pkt.addr2).swapcase()}")
			disasCounter=0
	
	# Look for authentication
	if pkt.haslayer(Dot11Auth) and pkt.addr1.casefold() in bssidList:
		authCounter+=1
		if authCounter >= 10:
			# Print alert
			print(f"{str(datetime.today())} Authentication Attack in progress from {str(pkt.addr2).swapcase()}")
			authCounter=0
	
	# Look for Beacon flods
	if pkt.haslayer(Dot11Beacon):
		beaconCounter+=1                                                                                                              
		if (beaconCounter >= 400):
			beaconFloodCounter+=1
			if beaconFloodCounter > 1:
				# Print Alert
				print(f"{str(datetime.today())} Beacon Flood Attack in progress")
				beaconCounter=0
				
			elif beaconFloodCounter > 10:
				beaconFloodCounter=0
				beaconCounter=0
				
	if pkt.haslayer(Dot11AssoReq) and pkt.addr1.casefold() in bssidList and not pkt.haslayer(Dot11EltRSN):
		print(f"{str(datetime.today())} Evil twin attack in progress --> {str(pkt[Dot11Elt].info)}")
		for char in ("Deauthing the client...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)
		# Deauthing client
		deauth_frame=RadioTap()/Dot11(type=0,subtype=12,addr1=pkt.addr1,addr2=pkt.addr2,addr3=pkt.addr1)/Dot11Deauth(reason=3)
		s = conf.L2socket(iface='wlan0')
		for i in range (1,1000):
			s.send(deauth_frame)
		#deauth_frame.addr1=='ff:ff:ff:ff:ff:ff'
		for i in range(1,1000):
			s.send(deauth_frame)
		
		for char in ("Ending the Deauth...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)
	
	if pkt.haslayer(Dot11AssoResp) or pkt.haslayer(Dot11ReassoResp) and pkt.addr2.casefold() in bssidList and not pkt.haslayer(Dot11EltRSN):
		print(f"{str(datetime.today())} Evil twin attack in progress --> {str(pkt.addr2)}")
		for char in ("Deauthing the client...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)
		# Deauthing client
		deauth_frame=RadioTap()/Dot11(type=0,subtype=12,addr1=pkt.addr2,addr2=pkt.addr1,addr3=pkt.addr1)/Dot11Deauth(reason=3)
		s = conf.L2socket(iface='wlan0')
		for i in range (1,1000):
			s.send(deauth_frame)
		#deauth_frame.addr1=='ff:ff:ff:ff:ff:ff'
		for i in range(1,1000):
			s.send(deauth_frame)
		
		for char in ("Ending the Deauth...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)

	# Spoof Attacks
	# Beacons
	elif pkt.haslayer(Dot11Beacon) and pkt.addr2.casefold() in bssidList and pkt.haslayer(Dot11Elt)==False:
		print(f"{str(datetime.today())} Spoofed Beacon Attack in progress Source: {str(pkt.addr2)}")
	# Probe Request
	elif pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt)==False and pkt.addr3.casefold() in bssidList:
			print(f"{str(datetime.today())} Spoofed Probe Request Attack in progress Source: {str(pkt.addr2)}")
	# Probe Response
	elif pkt.haslayer(Dot11ProbeResp) and pkt.addr2.casefold() in bssidList and pkt.haslayer(Dot11Elt)==False:
			print(f"{str(datetime.today())} Spoofed Probe Response Attack in progress Source: {str(pkt.addr2)}")
	# Association Request
	elif pkt.haslayer(Dot11AssoReq) and pkt.addr2.casefold() in bssidList and pkt[Dot11Elt].len==False:
			print(f"{str(datetime.today())} Spoofed Association Request Attack in progress")
	
	"""# Rogue Access Points
	if pkt.haslayer(Dot11ProbeReq) and pkt.addr1.casefold() not in bssidList:
		print(pkt.addr1.casefold())
		print(f"{str(datetime.today())} Rogue access point Attack in progress --> {str(pkt[Dot11Elt].info)} ")
		for char in ("Deauthing the client...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)
		# Deauthing client
		deauth = f"sudo timeout 20s mdk4 wlan0 d -B {pkt.addr1}"
		subprocess.run(deauth,shell=True,executable="/bin/bash")
		# Rogue Access Points
		
		for char in ("Ending the Deauth...\n"):
			print(char, end='',flush=True)
			time.sleep(0.05)
		
	# Evil Twin Attacks"""
	
		    
		
	
# Sniff while looking for deauth
sniff(iface='wlan0',prn=detect_attacks)
