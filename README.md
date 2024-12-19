# IDS
Authors: 4FTSQRL and KryptonPhantom

Summary: Basic IDS/IPS with Python for Linux Machine

This is primarily a python script, that needs to be run on a Linux machine that supports Scapy. You will also need a wireless adapter connected to the Linux machine/VM. 

For usage, create a whitelist text file that contains BSSIDs and their corresponding SSIDs to prevent the IDS/IPS from sending DoS attacks to trusted APs or false positives. It may be helpful to know which channel the AP you are protecting is on. To figure this out, use the command "sudo airodump -b abg wlan0" in the terminal on your Linux machine.