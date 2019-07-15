#!/usr/bin/python
#swap number of the partition in cmdLine for both partition
# the no current partition will be mount before modification
# then when we restart we will boot on the other partition

import subprocess
import os
import sys

#Partition Name
raspPartition = "mmcblk0p"

#Number of full and lite partition
raspFullNumber = "7"
raspLiteNumber = "9"
raspDataNumber = "10"

#Number of full and lite partition configuration
raspFullNumberConf = "6"
raspLiteNumberConf = "8"

#Path current Partition
currentPath = "/boot"

#Path data Partition
dataPath = "/mnt/data"

#Path other Partition
otherPath = "/mnt/tmp"

# detect if hash is pass as argument, or ask for debug mode
DEBUG = False
hash = ""
if (len(sys.argv[1:]) >= 1):
        if(len(sys.argv[1:]) >= 2):
            if(sys.argv[2] == "debug"):
                DEBUG = True
            hash = sys.argv[1]
        else:
	    if(sys.argv[1] == "debug"):
                DEBUG = True
            if(sys.argv[1] != "debug"):
                hash = sys.argv[1]

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
        return error
    return output


# this function change value of cmdline.txt file to boot to other partition
def changeBootOptions(pathFile,partitionName, newPartitionNumber):
    newContent = " "
    filename = pathFile+"/cmdline.txt"
    with open(filename, "r") as infile:
        lines = infile.readlines()
	fragments = lines[0].split(" ")
        for frag in fragments:
            if "root=" in frag:
                frag = "root=/dev/" + partitionName + newPartitionNumber
	    newContent = newContent + frag + " "
    newFile = open(filename, "w")
    newFile.write(newContent)
    newFile.close()

# this function will mount to other partition on /mnt/ to access cmdline file
def mountOtherPartition(otherPath, raspPartition, otherPartNumberConf):
    createFolder = "sudo mkdir " + otherPath
    mountPartition = "sudo mount -t auto /dev/" + raspPartition + otherPartNumberConf + " " +  otherPath
    sendBashCommand(createFolder)
    sendBashCommand(mountPartition)

# use this main if you are on the Full Raspbian partition
def mainOnRaspFull():
    # mount Data partition
    mountOtherPartition(dataPath,raspPartition,raspDataNumber)
    # clone updates files in data partition
    # normaly the following commands should allow us to recover the update files. Unfortunately, the solution used with Github
    # does not allow us to properly store these files and recover them easily.
   # getFiles = "wget -P /home/pi/ http://github.com/yannled/protectMe-Update/archive/tempUpdates.zip"
   # gitClone = "git clone https://github.com/yannled/protectMe-Update.git "+dataPath+"/protectMe-Update"
   # sendBashCommand(getFiles)
   # unzipFiles = "unzip /homepi/tempUpdates.zip -d "+dataPath+"/protectMe-Update"
   # sendBashCommand(unzipFiles)
   # deleteTemp = "sudo rm /home/pi/tempUpdates.zip"
   # sendBashCommand(deleteTemp)
    # get updateFile (.img) from reporitory git
    updateFile = []
    files = os.listdir(dataPath+"/protectMe-Update")
    for file in files:
        if ".img" in file:
		updateFile.append(file)

    # calcul hash of .img file (updateFile)
    fullHash =  ""
    computeHash = "find " + dataPath+"/protectMe-Update/*.img* -type f -print0 | xargs -0 sha1sum | awk '{print $1}' | sha1sum | awk '{print $1}'"
    fullHash = sendBashCommand(computeHash)
    if(fullHash == hash):
        # backup network files in data partition
	copyWpa_supplicantFile = "sudo cp /etc/wpa_supplicant/wpa_supplicant.conf "+dataPath+"/wpa_supplicant.conf"
	sendBashCommand(copyWpa_supplicantFile)
        copyDhcpcdFile = "sudo cp /etc/dhcpcd.conf "+dataPath+"/dhcpcd.conf"
	sendBashCommand(copyDhcpcdFile)
        # Modifiy partiton boot files to reboot to Lite Partition and do the update

        # change nummber partition for the current one
        changeBootOptions(currentPath,raspPartition,raspLiteNumber)

        # mount other partition to access cmdline file
        mountOtherPartition(otherPath, raspPartition, raspLiteNumberConf)

        # change number partition for the other one
        changeBootOptions(otherPath,raspPartition,raspFullNumber)

    reboot = "sudo reboot"
    sendBashCommand(reboot)

# use this main if you are on the Lite Raspbian Partition
def mainOnRaspLite():
    # mount Data partition
    mountOtherPartition(dataPath,raspPartition,raspDataNumber)

    # get updateFile (.img) from reporitory git
    updateFile = ""
    files = os.listdir(dataPath+"/protectMe-Update")
    for file in files:
        if ".img" in file:
                updateFile=file

    # clone new image to Full partition
    simpleUpdateFileName = updateFile.split(".")[0]
    updatePartition = "sudo cat "+dataPath+"/protectMe-Update/"+simpleUpdateFileName+".img.* | sudo gzip -dc | sudo dd of=/dev/"+raspPartition+raspFullNumber
    sendBashCommand(updatePartition)

    #change nummber partition for the current one
    changeBootOptions(currentPath,raspPartition,raspLiteNumber)

    #mount other partition to access cmdline file
    mountOtherPartition(otherPath, raspPartition, raspFullNumberConf)

    #change number partition for the other one
    changeBootOptions(otherPath,raspPartition,raspFullNumber)

    # copy backup network file from data partition to full partition
    copyWpa_supplicantFile = "sudo cp "+dataPath+"/wpa_supplicant.conf " +otherPath+ "/etc/wpa_supplicant/wpa_supplicant.conf"
    sendBashCommand(copyWpa_supplicantFile)
    copyDhcpcdFile = "sudo cp "+dataPath+"/dhcpcd.conf " +otherPath+ "/etc/dhcpcd.conf"
    sendBashCommand(copyDhcpcdFile)

    # remove git clone
    removeDir = "rm -r "+dataPath+"/protectMe-Update"
    sendBashCommand(removeDir)

    reboot = "sudo reboot"
    sendBashCommand(reboot)


if __name__ == "__main__":
    mainOnRaspFull()
    #mainOnRaspLite()
