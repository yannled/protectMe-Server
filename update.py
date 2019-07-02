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

#Number of full and lite partition configuration
raspFullNumberConf = "6"
raspLiteNumberConf = "8"

#Path current Partition
currentPath = "/boot"

#Path other Partition
otherPath = "/mnt/tmp"

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
    #change nummber partition for the current one
    changeBootOptions(currentPath,raspPartition,raspLiteNumber)

    #mount other partition to access cmdline file
    mountOtherPartition(otherPath, raspPartition, raspLiteNumberConf)

    #change number partition for the other one
    changeBootOptions(otherPath,raspPartition,raspFullNumber)

# use this main if you are on the Lite Raspbian Partition
def mainOnRaspLite():
    #change nummber partition for the current one
    changeBootOptions(currentPath,raspPartition,raspFullNumber)

    #mount other partition to access cmdline file
    mountOtherPartition(otherPath, raspPartition, raspFullNumberConf)

    #change number partition for the other one
    changeBootOptions(otherPath,raspPartition,raspLiteNumber)


if __name__ == "__main__":
    mainOnRaspFull()
    #mainOnRaspLite()

