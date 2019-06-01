#!/bin/python3

###################################################################
# Imports

#from scapy.all import *
import pyshark
import os
import gc

###################################################################
# "Hardcoded config"

pcapdir = "./pcaps/"
statsdir = "./stats/"
deleteExistingFile = True

###################################################################
# Funcs

def read_packets(filepath):
	size = os.path.getsize(filepath)
	size = size / 1024 / 1024 # to MB
	print("Reading packets from file ({0:.2f} MB)".format(size))
	if (size > 50):
		print("\tThis can take a bit :)")
	try:
		#packets = rdpcap(filepath)
		packets = pyshark.FileCapture(filepath, only_summaries=True) #pyshark.FileCapture(filepath, only_summaries=True) #rdpcap(filepath)
		#print("PCAP: {}".format(repr(packets[999])))
		return packets
	except MemoryError:
		return None
	except Scapy_Exception:
		print("This PCAP is invalid!")
		return None
	#except:
	#	print("Something went wrong reading the pcap file :(")
	#	return None

def get_protocol(packet):
	counter = 0
	ret = "Invalid"
	while True:
		layer = packet.getlayer(counter)
		if layer is None:
			if (ret == "TCP"):
				if (packet[TCP].sport == 80) or (packet[TCP].dport == 80):
					ret = "HTTP"
				if (packet[TCP].sport == 443) or (packet[TCP].dport == 443):
					ret = "HTTPS"
			return ret

		ret = layer.name
		counter += 1

def get_bytes(packet):
	return len(packet)

def get_destination_ip(packet):
	try:
		s_ip = packet[IP].src
		d_ip = packet[IP].dst

		if ("192.168" in s_ip) or ("145.100." in s_ip) or ("10.20.30" in s_ip):
			return d_ip

		return s_ip
	except IndexError:
		return "INVALID_IP_ADDRESS___NO_IP_LAYER"

def remove_file(filePath):
	try:
		os.remove(filePath)
	except OSError:
		pass

def store_results(destinationPath, gameName, protocolArray, bytesArray, ipArray):
	print("Saving stats for game \"{}\"".format(gameName))

	filePath = "{}{}".format(destinationPath, gameName)

	# Remove file if exists
	remove_file("{}_protocols.csv".format(filePath))
	remove_file("{}_bytes.csv".format(filePath))
	remove_file("{}_ipaddresses.csv".format(filePath))

	# Protocol
	with open("{}_protocols.csv".format(filePath), 'w+') as out:
		out.write("Protocol,Count\n")
		for key, value in protocolArray.items():
			out.write("{},{}\n".format(key, value))

	# Bytes
	with open("{}_bytes.csv".format(filePath), 'w+') as out:
		out.write("Protocol,Bytes\n")
		for key, value in bytesArray.items():
			out.write("{},{}\n".format(key, value))

	# IP addresses
	with open("{}_ipaddresses.csv".format(filePath), 'w+') as out:
		out.write("Destination IP,Count\n")
		for key, value in ipArray.items():
			out.write("{},{}\n".format(key, value))

	return

###################################################################
# Main

totalProtocolCounters = {}
totalProtocolBytes = {}
totalDestinationIPCounters = {}

gc.enable()

fileID = 0
totalFiles = len([name for name in os.listdir(pcapdir) if os.path.isfile(os.path.join(pcapdir, name))])

print("Analyzing files in the {} directory...".format(pcapdir))
for file in os.listdir(pcapdir):

	# Skip directory entries
	if (os.path.isdir(pcapdir + file)):
		continue

	# Skip if it has been analyzed, and the user requested it not being re-analyzed
	if (not deleteExistingFile):
		if (os.path.isfile("{}{}_protocols.csv".format(pcapdir, file))):
			print("Skipping {}; pcap is already analyzed".format(file))
			continue

	# Debug
	fileID += 1
	print("Analyzing {} ({}/{} ({}%))".format(file, fileID, totalFiles, round(100/totalFiles*fileID)))

	# Setting up
	protocolCounters = {}
	protocolBytes = {}
	destinationIPCounters = {}

	# Reading packets in dir
	#all_packets = read_packets(pcapdir + file)
	#if (all_packets is None):
	#	print("Failed to analyze {}; packets cannot be read".format(file))
	#	continue

	try:
		all_packets = pyshark.FileCapture(pcapdir + file, only_summaries=True) #pyshark.FileCapture(filepath, only_summaries=True) #rdpcap(filepath)
	except:
		print("Failed to read pcap file :(")
		continue

	# Analyze packets
	print("Analyzing packets that were read...")
	i = 0
	#packet_count = len(all_packets)
	#print("Found {} packets".format(packet_count))
	#interval = 1 + round(packet_count / 5)
	try:
		for packet in all_packets:
			#if (i % interval == 0):
			#print("\tAnalyzing packet {}...".format(i))

			#print("{}".format(packet))
			#2 0.013873 8.8.8.8 10.20.30.40 DNS 136 Standard query response 0x8024 A graph.facebook.com CNAME api.facebook.com CNAME star.c10r.facebook.com A 31.13.64.16
			packet = str(packet).split(" ")
			protocol = packet[4] #get_protocol(packet)
			bytes = int(packet[5]) #packet.length #get_bytes(packet)

			s_ip = packet[2]
			destination_ip = "UNKNOWN"
			if ("192.168" in s_ip) or ("145.100." in s_ip) or ("10.20.30" in s_ip):
				destination_ip = packet[3]
			else:
				destination_ip = packet[2]

			#destination_ip = "NOT_RECORDED" #get_destination_ip(packet)

			#protocol = packet[6] #get_protocol(packet)
			#bytes = packet[4] #get_bytes(packet)
			#destination_ip = packet[8] #get_destination_ip(packet)

			# Stats
			# Application
			if not (protocol in protocolCounters):
				protocolCounters[protocol] = 0
			protocolCounters[protocol] += 1

			if not (protocol in protocolBytes):
				protocolBytes[protocol] = 0
			protocolBytes[protocol] += bytes

			if not (destination_ip in destinationIPCounters):
				destinationIPCounters[destination_ip] = 0
			destinationIPCounters[destination_ip] += 1

			# Total
			if not (protocol in totalProtocolCounters):
				totalProtocolCounters[protocol] = 0
			totalProtocolCounters[protocol] += 1

			if not (protocol in totalProtocolBytes):
				totalProtocolBytes[protocol] = 0
			totalProtocolBytes[protocol] += bytes

			if not (destination_ip in totalDestinationIPCounters):
				totalDestinationIPCounters[destination_ip] = 0
			totalDestinationIPCounters[destination_ip] += 1

			i += 1
	except pyshark.capture.capture.TSharkCrashException:
		print("pyshark crashed ¯\_(ツ)_/¯")
		continue
	except:
		print("Cannot read packets ¯\_(ツ)_/¯")
		continue

	# Application results
	print("========================================")
	print("Protocol\tCount")
	for key, value in protocolCounters.items():
		print("{}\t{}\t".format(key, value))

	print("========================================")
	print("Protocol\tBytes")
	for key, value in protocolBytes.items():
		print("{}\t{}\t".format(key, value))

	print("========================================")
	print("Destination IP\tCount")
	for key, value in destinationIPCounters.items():
		print("{}\t{}\t".format(key, value))

	# Save to file
	store_results(statsdir, file, protocolCounters, protocolBytes, destinationIPCounters)

	# Cleanup
	all_packets = None
	protocolCounters = {}
	protocolBytes = {}
	destinationIPCounters = {}

	gc.collect()

	print("")

# Storing total results
print("Saving total results")
store_results(statsdir, "ALL_GAMES", totalProtocolCounters, totalProtocolBytes, totalDestinationIPCounters)

print("Done analyzing files!\n")

#store_results(protocol, bytes, destination_ip)
