#!/usr/bin/python
# source: rfcomm-server.py auth: Albert Huang <albert@csail.mit.edu> desc:

from bluetooth import *
import time
import base64
import re
import random
import subprocess
import string
import os
from Crypto.Cipher import AES
from datetime import datetime

rand_gen = random.SystemRandom()
from struct import *
import netifaces as ni
from Crypto.Util.number import long_to_bytes

# debug mode to show more information of running script
DEBUG = False
if (len(sys.argv[1:]) >= 1 and sys.argv[1] == "debug"):
    DEBUG = True

def log(s):
    if DEBUG:
        print(s)

def sendBashCommand(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (output, error) = process.communicate()
    process.wait()
    log("Command output: " + output)
    if error is not None:
        log("Command error: " + error)
        return "error: "+error
    return output

# Configure and connect to Wifi with ssid and password
def configureWifi(ssid, password):
    # stop interface wlan
    try:
        os.system("ifconfig wlan0 down")
        time.sleep(2)
    except:
        log("error during stop wifi")
        return "error during stop wifi"

    # get actual wpa configurations and saved wifi
    arrayOfLine = []
    filename = "/etc/wpa_supplicant/wpa_supplicant.conf"
    with open(filename, "r") as oldFile:
        for line in oldFile:
            arrayOfLine.append(line)
    os.remove(filename)

    # copy the first three lines
    #   ctrl_interfaces=...
    #   update_config=1
    #   country=CH
    # then write new wpa configuration
    counter = 0
    with open(filename, "a+") as wpa_supplicant:
        while (counter < 3):
            wpa_supplicant.write(arrayOfLine[counter])
            counter += 1
        wpa_supplicant.write("network={\n\tssid=\"" + ssid + "\"\n\tpsk=\"" + password + "\"\n\tkey_mgmt=WPA-PSK\n}")

    # restart interface wlan
    try:
        os.system("ifconfig wlan0 up")
        time.sleep(2)
        os.system("sudo wpa_cli -i wlan0 reconfigure")
        time.sleep(2)
    except:
        log("error during start wifi")
        return "error during stop wifi"
    return "ok"

# remove static IP and enable dhcp
def deleteStaticIP():
    filename = "/etc/dhcpcd.conf"
    with open(filename, "r") as infile:
        lines = infile.readlines()

    # rewrite all the content except three lines following "interface wlan0"
    position = -100
    with open(filename, "w") as outfile:
        for pos, line in enumerate(lines):
            if "interface wlan0" in line:
                position = pos
            if pos == position + 1:
                continue
            if pos == position + 2:
                continue
            if pos == position + 3:
                continue
            if "interface wlan0" not in line:
                outfile.write(line)

# configure static IP
def configureStaticIP(adresseIP, routerIP):
    filename = "/etc/dhcpcd.conf"

    # write the three lines for static configuration a the end of the file
    with open(filename, "a") as dhcpd:
        dhcpd.write(
            "interface wlan0\n\tstatic ip_address=" + adresseIP + "\n\tstatic routers=" + routerIP + "\n\tstatic domain_name_servers=" + routerIP + "\n")

# delete all old ovpn files and reinvoke old profiles
def deleteOldProfiles():
    PATH = "/home/pi/ovpns/"
    # delete files
    os.system("sudo " + PATH + " rm *")
    listProfileVPN = "pivpn -l"
    output = sendBashCommand(listProfileVPN)
    if "error" in output:
        return output
    # parse output to get profiles names
    profiles = output.split("\n")
    for profile in profiles:
        if ("Valid" in profile):
            profileName = profile[18:]
            # reinvoke profile
            delProfileVPN = "pivpn -r " + profileName
            output = sendBashCommand(delProfileVPN)
            if("error" in output):
                return output
    return "ok"

# Add new profile to piVpn
def addPiVpnProfile(profileName, profilePass):
    log(profileName)
    # addProfileVPN = "pivpn -a -n "+profileName+" -p "+profilePass
    addProfileVPN = "pivpn -a nopass -n " + profileName + " -d 1080"
    output = sendBashCommand(addProfileVPN)
    return output

# Generate new random password
def randomPassGen(size=8, chars=string.ascii_letters + string.digits + string.punctuation):
    return ''.join(random.choice(chars) for _ in range(size))

# Add portForwarding on the routeur through upnpc commands
def addPortForwardingThenReturnPubicIP():
    addPortForwarding = "upnpc -r 443 tcp"
    output = sendBashCommand(addPortForwarding)
    if "error" in output:
        return output

    lines = output.split("\n")
    for line in lines:
	if "ExternalIPAddress" in line:
		fragments = line.split(" ")
		ipPublic = fragments[2]
	        log("External IP : /" + ipPublic+"/")
                return ipPublic

def modifyPublicIpOvpnProfile(profile, publicIp):
    newProfile = ""
    lines = profile.split('\n')
    for line in lines :
	if('443' in line):
		line = "remote " + str(publicIp) + " 443"
        newProfile = newProfile + line + '\n'
    return newProfile

def formatProfileName(profileName):
    profileName = profileName.replace(" ", "_")
    profileName = profileName.replace("-", "_")
    profileName = profileName.replace(".", "_")
    profileName = profileName.replace(":", "_")
    profileName = profileName.lower()
    return profileName


# configure or Add new Profile by Bluetooth
def configureBox(client_sock):
    message = ""
    pattern = re.compile(r'\{(.*?)\}')
    try:
        while True:
            data = client_sock.recv(1024)
            message = message + data
            log("received [" + str(data) + "]")
            if ("endCryptoExchange" in data): break

        if ("endCryptoExchange" in data):
            print "begincrypto"
            # 1. split receive PublicKey, P and G (format : OpenSSLDHPublicKey{Y=...,P=...,G=...})

            #   Get params in {}
            receiveParams = pattern.findall(message)

            #   Get params in table
            params = receiveParams[0].split(',')

            #   Extract Receive Public key
            receiveKey = int(params[0][2:], 10)
            log("Receive publicKey : " + str(receiveKey))

            #   Exctract P and G
            p = int(params[1][2:], 10)
            g = int(params[2][2:], 10)
            log("g : " + str(g) + " p : " + str(p))

            # 2. Generate privateKey (Greater than 2 less than P)
            privateKey = rand_gen.randint(2, p - g)
            log("private Key : " + str(privateKey))

            # 3. Generate New Public key (pubKey = g**privateKey mod p)
            publicKey = pow(g, privateKey, (p))
            log("PublicKey : " + str(publicKey))
            log("PublicKey < p ?  :" + str(publicKey < p))

            # 4. Generate Shared Key (key = receivePubKey**privateKey mod p)
            sharedKeyInt = pow(receiveKey, privateKey, p)
            log("sharedKeyInt : " + str(sharedKeyInt))

            #   Convert it to Bytes
            sharedKeyBytes = long_to_bytes(sharedKeyInt)

            #   Reduce key as 16 Bytes
            sharedKey = sharedKeyBytes[:16]
            log("my key : " + sharedKey + " length : " + str(len(sharedKey)))

            # 5. Send public Key
            client_sock.sendall(str(len(str(publicKey))))
            client_sock.sendall(str(publicKey))

            # 6. Receive CypherText Wifi name then wifi password
            data = client_sock.recv(1024)
            log("cyphertext in base64 : " + data)

            #   Decode cyphertext
            data = base64.b64decode(data)
            log("nbr carac decode cyphertext : " + str(len(data)))
            log(" cyphertext : " + data)

            #   Extract IV
            iv = data[:16]

            # 7. Decrypt
            encryption_suite = AES.new(sharedKey, AES.MODE_CBC, iv)
            plaintext = encryption_suite.decrypt(data[16:])

            # if this is just an update we get the hash file then run update script
            if ("Update" in message):
                log("Update: file Hash : " + plaintext)
                hash = pattern.findall(plaintext)[0]
                log(hash)
                log("start update script")
                runUpdate = "sudo python /home/pi/protectMe-Server/update.py "+hash+ " debug"
                output = sendBashCommand(runUpdate)
                if "error" in output:
                    client_sock.sendall("error")

                print "disconnected"
                client_sock.close()
                print "all done"
		return

            # if not, we do the configuration or recuperation of profile
            log("Wifi name then wifi password : " + plaintext)

            wifiParams = pattern.findall(plaintext)
            wifiName = wifiParams[0]
            wifiPass = wifiParams[1]

            # 8. if this is a new configuration go into if. If this is just for adding profile bypass if.
            if ("FirstConfig" in message):
                log("First configuration")

                #   Configure WIFI and PIVPN ip static
                log("Configure Wifi")
                output = configureWifi(wifiName, wifiPass)
                if "error" in output:
                    client_sock.sendall("error")
                log("Delete static IP")
                deleteStaticIP()
                time.sleep(15)

                #   Configure PIVPN IP static
                log("configure static IP")
                ni.ifaddresses("wlan0")
                adresseIP = ni.ifaddresses("wlan0")[ni.AF_INET][0]['addr']
                splitIP = adresseIP.split(".")
                routerIp = splitIP[0] + "." + splitIP[1] + "." + splitIP[2] + "." + "1"

                configureStaticIP(adresseIP, routerIp)

                #  Delete old ovpnFiles and reinvoke olds profiles
                log("Delete old ovpn profiles")
                output = deleteOldProfiles()
                if "error" in output:
                    client_sock.sendall("error")

            # 9.  Add Port forwarding and get public IP
            publicIp = addPortForwardingThenReturnPubicIP()
            if "error" in publicIp:
                client_sock.sendall("error")

            # 10. Create OpenVpn Profile
            now = datetime.now()
            profileName = wifiName + str(now)
            profileName = formatProfileName(profileName)

            ovpnPassword = randomPassGen()
            log("Adding profile")
            output = addPiVpnProfile(profileName, ovpnPassword)
            if "error" in output:
                client_sock.sendall("error")

            # 11. Get openVpn profile (.ovpn file)
            PATH = "/home/pi/ovpns/"
            profileName = profileName + ".ovpn"
            ovpnFile = open(PATH + profileName, "r").read()

	    # 12. Modify public IP in the profile
            ovpnFile = modifyPublicIpOvpnProfile(ovpnFile, publicIp)

	    # 13. Send Profile
            #    Adding profilName and password in the beginning
            # ovpnFile = opvnProfileNamePassword + ovpnFile
            log(ovpnFile)

            # encrypt
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
    print "all done"


def main():
    while (True):
        # definition of the socket
        server_sock = BluetoothSocket(RFCOMM)
        server_sock.bind(("", PORT_ANY))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        # uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
        uuid = "00001101-0000-1000-8000-00805F9B34FB"

        advertise_service(server_sock, "SampleServer",
                          service_id=uuid,
                          service_classes=[uuid, SERIAL_PORT_CLASS],
                          profiles=[SERIAL_PORT_PROFILE]
                          )

        print("Waiting for connection on RFCOMM channel : " + str(port))
        client_sock, client_info = server_sock.accept()

        log("Accepted connection from " + str(client_info))

        configureBox(client_sock)


if __name__ == "__main__":
    main()
