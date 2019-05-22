# file: rfcomm-server.py auth: Albert Huang <albert@csail.mit.edu> desc: 
# simple demonstration of a server application that uses RFCOMM sockets#
# $Id: rfcomm-server.py 518 2007-08-10 07:20:07Z albert $

from bluetooth import *
import time
import base64
import re
import random
import subprocess
import sys
import string
import os
from Crypto.Cipher import AES
from datetime import datetime
rand_gen = random.SystemRandom()
from Crypto import Random
from struct import *
import netifaces as ni
from Crypto.Util.number import long_to_bytes

#debug mode to show more information of running script
DEBUG = False
if(len(sys.argv[1:])>=1 and sys.argv[1]=="debug"):
	DEBUG = True

#definition of the socket
server_sock=BluetoothSocket( RFCOMM )
server_sock.bind(("",PORT_ANY))
server_sock.listen(1)
port = server_sock.getsockname()[1]

#uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
uuid = "00001101-0000-1000-8000-00805F9B34FB"

advertise_service( server_sock, "SampleServer",
       	           service_id = uuid,
               	   service_classes = [ uuid, SERIAL_PORT_CLASS ],
               	 profiles = [ SERIAL_PORT_PROFILE ] 
               	)

def log(s):
        if DEBUG:
            print(s)


def configureWifi(ssid, password):
	try:
		os.system("ifconfig wlan0 down")
		time.sleep(2)
	except:
		log("error during stop wifi")

	arrayOfLine = []
	filename = "/etc/wpa_supplicant/wpa_supplicant.conf"
	with open(filename, "r") as oldFile:
		for line in oldFile:
			arrayOfLine.append(line)
	os.remove(filename)

	counter = 0
    	with open(filename, "a+") as wpa_supplicant:
		while(counter<3):
			wpa_supplicant.write(arrayOfLine[counter])
			counter+=1
		wpa_supplicant.write("network={\n\tssid=\""+ssid+"\"\n\tpsk=\"" + password + "\"\n\tkey_mgmt=WPA-PSK\n}")

	try:
		os.system("ifconfig wlan0 up")
		time.sleep(2)
		os.system("sudo wpa_cli -i wlan0 reconfigure")
		time.sleep(2)
	except:
		log("error during start wifi")


def deleteStaticIP():
	filename = "/etc/dhcpcd.conf"
        with open(filename,"r") as infile:
	        lines = infile.readlines()

        position = -100
        with open(filename,"w") as outfile:
                for pos, line in enumerate(lines):
                        if "interface wlan0" in line:
                                print(line)
                                position = pos
                        if pos == position+1 :
                                continue
                        if pos == position+2 :
                                continue
                        if pos == position+3  :
                                continue
                        if "interface wlan0" not in line:
                                outfile.write(line)


def configureStaticIP(adresseIP,routerIP):
	filename = "/etc/dhcpcd.conf"

	with open(filename,"a") as dhcpd:
		dhcpd.write("interface wlan0\n\tstatic ip_address="+adresseIP+"\n\tstatic routers="+routerIP+"\n\tstatic domain_name_servers="+routerIP+"\n")


def addPiVpnProfile(profileName, profilePass):
	log(profileName)
	#addProfileVPN = "pivpn -a -n "+profileName+" -p "+profilePass
	addProfileVPN = "pivpn -a nopass -n "+profileName
	process = subprocess.Popen(addProfileVPN, stdout=subprocess.PIPE, shell=True)
        (output, error) = process.communicate()
        p_status = process.wait()
	log("Command output: " + output)
	if error is not None:
		log("Command error: " + error)

def randomPassGen(size=8, chars=string.ascii_letters + string.digits + string.punctuation):
	return ''.join(random.choice(chars) for _ in range(size))

def configureBox(client_sock):
    message =""
    pattern = re.compile(r'\{(.*?)\}')
    try:
        while True:
            data = client_sock.recv(1024)
            message = message + data
       	    log("received [" +  str(data)+"]")
	    if("endCryptoExchange" in data) : break

        if("endCryptoExchange" in data) :
		print "begincrypto"
            	#1. split receive PublicKey, P and G (format : OpenSSLDHPublicKey{Y=...,P=...,G=...})

            	#   Get params in {}
		receiveParams = pattern.findall(message)

		#   Get params in table
            	params = receiveParams[0].split(',')

            	#   Extract Receive Public key
                receiveKey = int(params[0][2:],10)
		log("Receive publicKey : " + str(receiveKey))
                #   Exctract P and G
                p = int(params[1][2:],10)
                g = int(params[2][2:],10)
		log("g : " + str(g) + " p : " + str(p))

                #2. Generate privateKey (Greater than 2 less than P)
                privateKey =  rand_gen.randint(2,p-g)
		log("private Key : " + str(privateKey))

                #3. Generate New Public key (pubKey = g**privateKey mod p)
                publicKey = pow(g, privateKey, (p))
		log("PublicKey : " + str(publicKey))
		log("PublicKey < p ?  :" + str(publicKey < p) )

                #4. Generate Shared Key (key = receivePubKey**privateKey mod p)
                sharedKeyInt = pow(receiveKey, privateKey, p)
		log("sharedKeyInt : " + str(sharedKeyInt))
		#   Convert it to Bytes
		sharedKeyBytes = long_to_bytes(sharedKeyInt)
		#   Reduce key as 16 Bytes
                sharedKey =  sharedKeyBytes[:16]
		log("my key : " + sharedKey + " length : " + str(len(sharedKey)))
		print(sharedKey)
                #5. Send public Key
		client_sock.sendall(str(len(str(publicKey))))
		client_sock.sendall(str(publicKey))

                #6. Receive CypherText Wifi name then wifi password
		data = client_sock.recv(1024)
		log("cyphertext in base64 : " + data)
		#   Decode cyphertext
		data = base64.b64decode(data)
		log("nbr carac decode cyphertext : " + str(len(data)))
		log(" cyphertext : " + data)
		#   Extract IV
		iv = data[:16]

		#7. Decrypt
		encryption_suite = AES.new(sharedKey, AES.MODE_CBC,iv)
		plaintext = encryption_suite.decrypt(data[16:])
		print("Wifi name then wifi password : " + plaintext)

		wifiParams = pattern.findall(plaintext)
		wifiName = wifiParams[0]
		wifiPass = wifiParams[1]
		#8 Si c'est une configuration faire le if, si c'est juste un ajoute
		#  de smartphone alors eviter.
		if("FirstConfig" in message) :
			log("First configuration")
			#   Configure WIFI and PIVPN ip static
			configureWifi(wifiName,wifiPass)
			deleteStaticIP()
			time.sleep(15)
	        	#   Configure PIVPN IP static 
			ni.ifaddresses("wlan0")
        		adresseIP = ni.ifaddresses("wlan0")[ni.AF_INET][0]['addr']
        		splitIP = adresseIP.split(".")
        		routerIp = splitIP[0]+"."+ splitIP[1]+"."+ splitIP[2] +"."+"1"

			configureStaticIP(adresseIP,routerIp)
	        #9.  Create OpenVpn Profile
		now = datetime.now()
        	profileName = wifiName+str(now)
		# TODO FAIRE FONCTION AVEC TOUS CARAC FORMATAGE
        	profileName = profileName.replace(" ","-")
		profileName = profileName.replace("_","-")
		profileName = profileName.replace(".","-")
		profileName = profileName.replace(":","-")

		ovpnPassword = randomPassGen()
		addPiVpnProfile(profileName, ovpnPassword)
		#opvnProfileNamePassword = "<auth-user-pass>\n"+profileName+"\n"+ovpnPassword+"\n</auth-user-pass>\n"
		opvnProfileNamePassword = "<auth-user-pass>\n"+"test"+"\n"+"test"+"\n</auth-user-pass>\n"
		#10. send openVpn profile (.ovpn file)
		PATH = "/home/pi/ovpns/"
		profileName = "test"+".ovpn"
		ovpnFile = open(PATH+profileName,"r").read()

		#    Adding profilName and password in the beginning
		ovpnFile = opvnProfileNamePassword + ovpnFile
		print(ovpnFile)

		#   Send
		pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
		ovpnFile = pad(ovpnFile)
                cipher = AES.new(sharedKey, AES.MODE_CBC, iv)
		cipherText = base64.b64encode(iv + cipher.encrypt(ovpnFile))
		# Send length of ovpn cyphertext
		client_sock.sendall(str(len(str(cipherText))))
		# Receive acquitement
		data = client_sock.recv(1024)
		# Send cyphertext
		client_sock.sendall(cipherText)

    except IOError:
        pass

    print "disconnected"

    client_sock.close()
    server_sock.close()
    print "all done"


def main():
	while(True):
		log("Waiting for connection on RFCOMM channel : " + str(port))
		client_sock, client_info = server_sock.accept()

		log("Accepted connection from " + str(client_info))

		#actionChoice = ""
		#data = client_sock.recv(1024)

		configureBox(client_sock)

if __name__ == "__main__":
	#configureWifi("wifideTest", "123456eartzui")
	#configureStaticIP("10.0.0.34","10.0.0.1")
        #ni.ifaddresses("wlan0")
        #adresseIP = ni.ifaddresses("wlan0")[ni.AF_INET][0]['addr']
	#print(adresseIP)
	#splitIP = adresseIP.split(".")
	#routerIp = splitIP[0]+"."+ splitIP[1]+"."+ splitIP[2] +"."+"1"
	#print(routerIp)
	#ProfileName = "bounboubnboub"
	#password = "zolozo"
	#addProfileVPN = "pivpn -a -n "+ProfileName+" -p "+password
	#process = subprocess.Popen(addProfileVPN, stdout=subprocess.PIPE, shell=True)
	#(output, error) = process.communicate()
	#p_status = process.wait()
	addPiVpnProfile("test3","test3")
	#main()

