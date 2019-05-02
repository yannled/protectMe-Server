# file: rfcomm-server.py auth: Albert Huang <albert@csail.mit.edu> desc: 
# simple demonstration of a server application that uses RFCOMM sockets#
# $Id: rfcomm-server.py 518 2007-08-10 07:20:07Z albert $

from bluetooth import *
import base64
import re
import random
import sys
import os
from Crypto.Cipher import AES
rand_gen = random.SystemRandom()
from Crypto import Random
from struct import *
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

def configureBox():
    message =""
    pattern = re.compile(r'\{(.*?)\}')
    try:
        while True:
            data = client_sock.recv(1024)
            if len(data) == 0: break
            message = message + data
        log("received [" +  str(data)+"]")

        if("endCryptoExchange" in data) :
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

                #6. Receive CypherText
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
		print("plaintext : " + plaintext)

		#8 Si c'est une configuration faire le if, si c'est juste un ajoute
		#  de smartphone alors éviter.
		if("configuration" in data) :
			#   Configure WIFI

	        	#   Configure PIVPN IP static 

	        	#   Create OpenVpn Profile

		#8. send openVpn profile (.ovpn file)
		PATH = "/home/pi/ovpns/"
		ovpnFile = open(PATH+"test.ovpn","r").read()
		print(ovpnFile)
		#ipv4 = str(os.popen('ip addr show wlan0').read().split("inet ")[1].split("/")[0])
		#log(ipv4)

		#   Send
		#pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
		#ovpnFile = pad(ovpnFile)
                #cipher = AES.new(sharedKey, AES.MODE_CBC, iv)
		#cipherText = base64.b64encode(iv + cipher.encrypt(ovpnFile))
		#client_sock.sendall(str(len(str(cipherText))))
		#client_sock.sendall(cipherText)
		print(str(ovpnFile))
		print(len(ovpnFile))
		print(str(len(ovpnFile)))
		#send length
		client_sock.sendall(str(len(str(ovpnFile))))
		# receive acquitement
		data = client_sock.recv(1024)
		# send Data
                client_sock.sendall(ovpnFile)


    except IOError:
        pass

    print "disconnected"

    client_sock.close()
    server_sock.close()
    print "all done"


def main():
	while(true)
		log("Waiting for connection on RFCOMM channel : " + str(port))

		client_sock, client_info = server_sock.accept()
		log("Accepted connection from " + str(client_info))

		actionChoice = ""
		data = client_sock.recv(1024)

		configureBox(data)
