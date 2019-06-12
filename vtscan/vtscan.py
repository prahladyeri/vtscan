##
# VTScan - Utility to scan for malicious files using the VirusTotal API
#
# @author Prahlad Yeri<prahladyeri@yahoo.com>
# @license MIT
# @modified 13-05-2019
#
import requests
import argparse
import os, sys
import time
import hashlib
import json
from vtscan import __title__, __description__, __version__

def checkkey(kee):
	try:
		if len(kee) == 64:
			return kee
		else:
			print("There is something wrong with your key. Not 64 Alpha Numeric characters.")
			exit()
	except e as Exception:
			print(e)
			
def checkhash(hsh):
	try:
		if len(hsh) == 32:
			return hsh
		elif len() == 40:
			return hsh
		elif len(hsh) == 64:
			return hsh
		else:
			print("The Hash input does not appear valid.")
			exit()
	except e as Exception:
			print(e)
			
def fileexists(filepath):
	try:
		if os.path.isfile(filepath):
			return filepath
		else:
			print("There is no file at:" + filepath)
			exit()
	except Exception as ex:
			print(ex)


def scan(hash, log_output=False):
	#read key from config.json
	apppath = os.path.dirname(os.path.realpath(__file__))
	#print("apppath: ", apppath)
	cfname = os.path.join(apppath, 'config.json')
	fp = open(cfname, 'r')
	ss = fp.read()
	#print("ss: ", ss)
	obj = json.loads(ss)
	fp.close()
	#print("obj: ", obj)
	#print('foo')
	if obj['api_key'] == "":
		print("VirusTotal API key is empty.\nKindly register an account on https://www.virustotal.com if you haven't, get your API Key from community profile and then put it in:\n\n" + cfname + ".\n\nRefer this link for more help: https://www.virustotal.com/en/documentation/public-api/")
		return

	#print("verbose output: ",verbose)
	params = {'apikey': obj['api_key'], 'resource': hash, } #'allinfo': verbose
	url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	json_response = url.json()
	if log_output:
		ss = json.dumps(json_response)
		open('output.json','w').write(ss)
		print("Logged output to output.json")
	response = int(json_response.get('response_code'))
	if response == 0:
		print ('Not found in VT Database')
	elif response == 1:
		print ('Found in VT Database')
		print ("permalink: ", json_response.get('permalink'))
		positives = int(json_response.get('positives'))
		# mcafee = str(json_response.get('report'))
		print("Number of positives: ", positives)
		if positives == 0:
			print (hash + ' is not malicious')
		else:
			print (hash + ' is malicious')
		scans = json_response.get('scans')
		for key in scans:
			if scans[key]['detected']: print(key, "v", scans[key]['version'], ": ", scans[key]['detected'])
			
	else:
		print (hash + ' could not be searched. Please try again later.')
	print("")
	#print(json_response)

def main():
	banner = """%s version %s
%s

Copyright (c) 2019 Prahlad Yeri. All rights reserved.

This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.
""" % (__title__, __version__, __description__)
	print(banner)
	parser = argparse.ArgumentParser()
	parser.add_argument('input_file', type=fileexists, help='Input File Location EX: /Desktop/Somewhere/input.txt')
	parser.add_argument('-l', '--log-output',  default=False, action='store_true', help='Log output to json file')
	parser.add_argument('-v', '--version', help='Version', action='store_true')
	args = parser.parse_args()
	
	if args.version:
		sys.exit()
	# if args.input_file is None:
		# parser.error("input_file is required")
	#calculate hash of file
	hash = hashlib.sha1()
	with open(args.input_file,'rb') as fp:
		for chunk in iter(lambda: fp.read(4096), b""):
			hash.update(chunk)
	strhash = hash.hexdigest()
	scan(strhash.strip(), args.log_output) #args.verbose

# execute the program
if __name__ == '__main__':
	main()
