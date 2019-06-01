#!/bin/python3

import os

statsdir = "./stats/"

protocolCount = {}

outFile = open("protocol_count.csv", "a")
outFile.truncate()
outFile.write("Protocol,Game count\n")

for filename in os.listdir(statsdir):
	if (not "nomitm" in filename):
		continue

	if (not "protocols" in filename):
		continue

	if (os.path.isdir(statsdir+filename)):
		continue

	print("Processing {}...".format(filename))
	firstLine = True
	with open(statsdir + filename) as f:
		for line in f:
			if (firstLine):
				firstLine = False
				continue
			else:
				line = line.replace("\n", "").split(",")
				if (not line[0] in protocolCount):
					protocolCount[line[0]] = 0
				protocolCount[line[0]] += 1

for key,value in protocolCount.items():
	outFile.write("{},{}\n".format(key, value))

outFile.close()
