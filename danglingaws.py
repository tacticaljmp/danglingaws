# Author: tacticaljmp

# python danglingaws.py
# For options, consider "python danglingaws.py -h".

# This tool leverages the Boto3 API.
# For the tool to work properly, prepare account access via "aws configure" first.
# Using the AWS SecurityAudit policy is recommended.


# TODO:
#
# - fix number incoherency between identified log files and the progress bar
# - check missing IPs against current EC2 instances' public IPs (and generate warnings) in checkDomains
# - probably differentiate between network interface IPs and Elastic IPs during evaluation
#	-> unreserved IPs from network interfaces can still be dangerous


import eventlet
import boto3
import os
import gzip
import json
import socket
import argparse
import urllib
import ipaddress
from progress.bar import Bar


# Checks if path contains anything. If it contains anything, user input decides whether all files shall
# be removed from the folder or not. However, any folders in the path will not be removed.
# 
# path:			The path to prepare.
#
def prepareLogFolder(path):
	if not os.path.exists(path):
		os.makedirs(path)
	else:
		if os.listdir(path):
			print("Specified download folder is not empty - it should be empty though to run everything smoothly. Empty the folder (ALL FILES WILL BE DELETED)? (y/n)")
			while True:
				answer = raw_input()
				if answer == "y":
					for file in os.listdir(path):
						if os.path.isfile(path + file):
							os.remove(path + file)
					break
				elif answer == "n":
					break
			

# Downloads a single file from a S3 bucket.
#
# bucketName:		The name of the S3 bucket to download from.
# key:				The AWS key of the file to be downloaded.
# toPath:			The relative local path where the downloaded file shall be stored.
#
# Returns True on success, or false if downloading failed.
#
def downloadSingleFile(bucketName, key, toPath):
	try:
		s3 = boto3.resource("s3")		
		s3.meta.client.download_file(bucketName, key, toPath + str(key).replace("/", ""))	
	except:
		print("Download of file " + str(key) + "failed. ")
		return False	
	return True


# Retrieves the content of a file as string.
#
# logfile:			The relative path of the file to read from.
# isZipped:			If true, the file is unzipped before reading.
#					AWS log files are zipped by default.
#
# Returns the content of the file as string on success, or an empty string if reading failed.
#
def getLogfileContent(logfile, isZipped = True):
	try:
		if isZipped:
			with gzip.open(logfile) as f:
				return str(f.read())
		else:
			f = open(logfile, "r")
			return str(f.read())
	except:
		return ""

	
# Iterates all CloudTrails of the configured AWS account and tries to identify and download all
# log files from the respective S3 buckets. Uses multiple threads to speed up the download.
#
# toPath:			The relative path where the downloaded log files will be stored. This folder
#					should be empty.
# fileLimit:		Sets a maximum of log files to be downloaded. This limit is applied after
#					the filtering.
# threads:			Sets the maximum number of threads to be spawned for parallel downloads.
#
# Returns the number of downloaded log files on success, or -1 in case of failure.
#
def downloadLogfiles(toPath, fileLimit, threads):
	# Check if download path exists and if it is empty
	prepareLogFolder(toPath)
	
	# Get trails for account's current region
	print("Iterating CloudTrails ...")
	try:
		client = boto3.client("cloudtrail")	
		trailList = client.describe_trails()["trailList"]
	except:
		print("Iterating CloudTrails failed. ")
		return -1

	# Iterate trails and retrieve log files
	for trail in trailList:
		print("Found trail in current region: ")
		print(trail["Name"])
		print("Corresponding log bucket is ")
		print(trail["S3BucketName"])

		# Access log buckets
		try:
			s3 = boto3.resource("s3")
			bucket = s3.Bucket(trail["S3BucketName"])
		except:
			print("Accessing log bucket " + trail["S3BucketName"] + " failed. ")
			return -1

		# Identify log files	
		print("Identifying log files... ")	
		try:
			# Assemble log file key prefix
			client = boto3.client("sts")
			accountID = client.get_caller_identity()["Account"]	

			if trail.has_key("S3KeyPrefix"):				
				prefix = trail["S3KeyPrefix"] + "/"
			else:
				prefix = ""		

			# Filter bucket contents for potential log files. Sort out the digest files.
			logfiles = bucket.objects.filter(Prefix = "AWSLogs/" + prefix + accountID + "/" + "CloudTrail/")

			print("Found " + str(len(list(logfiles))) + " log files.")

			if fileLimit == 0:
				print("INFO: File limit is set to unlimited. ")								
			else:
				print("INFO: File limit is set to " + str(fileLimit) + ". ")		
				logfiles = logfiles.limit(fileLimit)				
		except:
			print("Identification of log files failed.")
			return -1
		
		# Prompt for continuing
		print("Ready to download log files - this may take a while. Proceed? (y/n)")
		while True:
			answer = raw_input()
			if answer == "y":					
				break
			elif answer == "n":
				print("No download.")
				return 0
			
		print("INFO: Using " + str(threads) + " threads ... ")
		
		try:
			# Spawning threads to parallelize downloads
			bar = Bar("Downloading...", max = len(list(logfiles)))
			pool = eventlet.GreenPool(size = threads)				
			for logfile in logfiles:
				pool.spawn(downloadSingleFile, trail["S3BucketName"], logfile.key, toPath)
				bar.next()
			pool.waitall()
			bar.finish()
		except:
			print("Download of log files for trail " + trail["Name"] + " failed.")
			return -1
			
	print("Download finished.")
	return len(list(logfiles))


# Evaluates AWS log files. Crawls the files for all releaseAddress() calls and identifies potentially
# dangerous IPs by checking if these released addresses have ever been associated to an EC2 instance
# or network interface.
#
# fromPath:			The relative local path of the log files to be evaluated.
#
# Returns a list of potentially dangerous released IPs.
#
def evaluateLogfiles(fromPath):
	releasedIPs = []	
	associatedIDs = []
	allocatedIPMap = {}
	releasedIDs = []
	
	print("Evaluating log files for releaseAddress() calls ... ")
	
	try:
		for filename in os.listdir(fromPath):
			if os.path.isfile(fromPath + filename):
				try:
					currentContent = getLogfileContent(fromPath + filename)		
					records = json.loads(currentContent)["Records"]
				except:
					print("Failed to interpret JSON from log file " + fromPath + filename)		
					continue
				try:
					# Find allocationIds of allocated IPs and map them
					for event in records:
						if event["eventName"] == "AllocateAddress":				
							allocatedIPMap[str(event["responseElements"]["allocationId"])] = str(event["responseElements"]["publicIp"])
					# Find allocationIds of released IPs
					for event in records:
						if event["eventName"] == "ReleaseAddress":
							releasedIDs.append(str(event["requestParameters"]["allocationId"]))	
					# Find allocationIds of associated IPs
					for event in records:
						if event["eventName"] == "AssociateAddress":
							associatedIDs.append(str(event["requestParameters"]["allocationId"]))
				except:
					print("Failed to gather required information from log file " + fromPath + filename)		
					continue
	except:
		print("Failed in accessing local log files!")		
		
	# Discard all releasedIDs that have never been associated
	releasedIDs = list(set(releasedIDs) & set(associatedIDs))
	
	# Resolve releasedIPs via mapping	
	for releasedID in releasedIDs:
		try:
			releasedIPs.append(allocatedIPMap[releasedID])
		except:
			print("Could not resolve IP address with allocation ID " + releasedID)
				  
	# Remove duplicate entries
	releasedIPs = list(set(releasedIPs))
	
	print("Evaluation done.")
	
	return releasedIPs


# Retrieves all currently associated public IPs for all EC2 instances and network interfaces for
# the configured AWS account.
#
# Returns a list of associated public IPs.
#
def getCurrentIPs():
	currentIPs = []
	
	print("Retrieving currently associated public IPs from EC2 instances and network interfaces ...")
	
	try:
		client = boto3.client("ec2")	
	except:
		print("Accessing AWS failed ...")
		return currentIPs
		
	# Get public IPs from current EC2 instances
	try:
		instances = client.describe_instances()		
		for instance in instances["Reservations"][0]["Instances"]:
			if instance.has_key("PublicIpAddress"):
				currentIPs.append(instance["PublicIpAddress"])	
	except:
		print("Failed to retrieve public IPs from current EC2 instances.")
		
	# Get public IPs from current EC2 network interfaces
	try:
		interfaces = client.describe_network_interfaces()	
		for interface in interfaces["NetworkInterfaces"]:
			if interface.has_key("Association"):
				currentIPs.append(interface["Association"]["PublicIp"])
	except:
		print("Failed to retrieve public IPs from current EC2 network interfaces.")
			
	# Remove duplicate entries
	currentIPs = list(set(currentIPs))	
	
	print("Done.")
	
	return currentIPs


# Reads a list of domains from a local file. The function DNS-resolves the domains and checks whether
# the acquired IPs are in AWS IP range. The AWS acccount is then queried for currently allocated Elastic IPs.
# The function outputs a list of all AWS IPs in the given domain scope that are not permanently bound to the account.
#
# domainFile:		The relative local path to a file that contains the domains to check, one per line.
#
# Returns true on success. Returns false if an exception is thrown.
#
def checkDomains(domainFile):
	# Read list of domains from file
	print("Reading domains from file " + domainFile + " ...")
	domains = []
	try:
		with open(domainFile, "r") as file:
			for line in file:
				domains.append(line.replace("\n", ""))
		print("Done.")
	except:
		print("Error reading from domain file " + domainFile)
		return False
	
	# Do DNS lookup
	print("Performing DNS lookup for domains ...")
	ips = []
	for domain in domains:
		try:
			currentIP = socket.gethostbyname(domain)
			print(domain + "\t\t" + currentIP) 
			ips.append(currentIP)
		except:
			print("Error resolving " + domain + ". Skipping.")
	print("Done.")
	
	# Get current AWS range file
	print("Reading AWS IP range file from https://ip-ranges.amazonaws.com/ip-ranges.json ...")
	try:
		rangefile = urllib.urlopen("https://ip-ranges.amazonaws.com/ip-ranges.json").read()
		ranges = json.loads(rangefile)
		print("Done.")
	except:
		print("Failed.")
		return False
	
	# Filter IPs for AWS range
	try:
		filteredIPs = []
		for ip in ips:
			for prefix in ranges["prefixes"]:
				if ipaddress.ip_address(ip.decode("unicode-escape")) in ipaddress.ip_network(prefix["ip_prefix"]):
					filteredIPs.append(ip)
		# Remove duplicate entries
		filteredIPs = list(set(filteredIPs))
	except:
		print("Error while filtering IPs for AWS range.")
		return False
	print("IPs in AWS range: ")
	for filteredIP in filteredIPs:
		print(filteredIP)
			
	# Get currently allocated Elastic IPs
	print("Retrieving currently allocated Elastic IPs ...")
	try:
		client = boto3.client("ec2")
		elasticIPs = []
		for address in client.describe_addresses()["Addresses"]:
			elasticIPs.append(address["PublicIp"])
			
		if elasticIPs:
			for elasticIP in elasticIPs:
				print(elasticIP)
		else:	
			print("None allocated.")			
	except:
		print("Could not retrieve Elastic IPs.")
		return False
	
	# Calculate missing IPs = filtered IPs - elastic IPs	
	missingIPs = list(set(filteredIPs) - set(elasticIPs))
	
	# Print out findings
	print("\nThe following IPs in scope are not part of your Elastic IPs: ")
	for missingIP in missingIPs:
		print(missingIP)
	
	return True



		
# MAIN --------------------------------------------------

# Argument handling
parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-offline", action = "store_true", default = False, help = "Set this flag to disable download from AWS. Only log files specified by the path argument are evaluated.")
parser.add_argument("-path", action = "store", default = "logs/", help = "Specifies the relative path where downloaded log files from AWS will be/are stored.")
parser.add_argument("-threads", action = "store", type = int, default = 256, help = "Sets the maximum number of threads to be spawned for parallel log file download.")
parser.add_argument("-fileLimit", action = "store", type = int, default = 0, help = "Sets a limit for how many log files will be downloaded from AWS. This limit is applied after the filtering. Set to 0 to remove the limit.")
parser.add_argument("-checkDomains", action = "store_true", default = False, help = "Option to check a given list of domains. No log files will be downloaded and evaluated, instead the tool will check if any of the given domains' IPs are not linked to one of your Elastic IPs.")
parser.add_argument("-domainFile", action = "store", default = "domains.txt", help = "Specify this to set an alternative input file for domains to be checked via the checkDomains option. The tool will expect the file to contain one domain per line.")
args = parser.parse_args()

if args.checkDomains:
	checkDomains(args.domainFile)
else:	
	# Eventlet preparation (necessary for download threading)
	eventlet.monkey_patch(all = True)

	# Option to skip download
	if not args.offline:	
		downloadLogfiles(args.path, args.fileLimit, args.threads)

	# Evaluate log files and get released IPs
	releasedIPs = evaluateLogfiles(args.path)

	# Retrieve currently associated IPs
	currentIPs = getCurrentIPs()

	# Sort out the currently associated IPs
	releasedIPs = list(set(releasedIPs) - set(currentIPs))

	# Do reverse DNS lookup on the potentionally dangerous IPs
	# Print out the findings, including aliases
	print("\nReleased IP findings (with their current domains): \n")
	for releasedIP in releasedIPs:
		try:
			dnsResponse = socket.gethostbyaddr(releasedIP)
			print(releasedIP + "\t\t" + dnsResponse[0])
			for alias in dnsResponse[1]:
				print("\t\t" + alias)
		except:
			print("Reverse DNS failed for address " + releasedIP)
