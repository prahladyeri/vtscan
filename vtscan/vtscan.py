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
from cfgsaver import cfgsaver
from vtscan import __title__, __description__, __version__
from colorama import Fore, Style

pkg_name = "vtscan"
config_keys = ['api_key']
config = cfgsaver.get(pkg_name)


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
	if 'api_key' not in config or config['api_key'] == "":
		raise Exception("api key is missing")
		return

	#print("verbose output: ",verbose)
	params = {'apikey': config['api_key'], 'resource': hash, } #'allinfo': verbose
	url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	json_response = url.json()
	if log_output:
		ss = json.dumps(json_response, indent=4)
		open('output.json','w').write(ss)
		print("Logged output to output.json")
	response = int(json_response.get('response_code'))
	if response == 0:
		print (Fore.YELLOW + 'Not found in VT Database' + Fore.RESET)
	elif response == 1:
		print ('Found in VT Database')
		print ("permalink: ", json_response.get('permalink'))
		positives = int(json_response.get('positives'))
		total = int(json_response.get('total'))
		# mcafee = str(json_response.get('report'))
		print("Number of positives: %d (out of %d scanners applied)" % (positives, total))
		#print("sha1: %s" % json_response.get('sha256'))
		print("verbose_msg: %s" % json_response.get('verbose_msg'))
		if positives == 0:
			print(Fore.GREEN + hash + ' is not malicious' + Fore.RESET)
		else:
			print(Fore.RED + hash + ' is malicious' + Fore.RESET)
		scans = json_response.get('scans')
		for key in scans:
			if scans[key]['detected']: 
				print(Fore.RED, key, "v", scans[key]['version'], ": ", scans[key]['detected'], Fore.RESET)
			
	else:
		print (hash + ' could not be searched. Please try again later.')
	print("")
	#print(json_response)


def main():
	global config
	#print('DEBUG', set(['-v', '--version']), sys.argv)
	if '-v' in sys.argv or '--version' in sys.argv:
		print( "%s version %s" % (__title__, __version__) )
		return
	parser = argparse.ArgumentParser()
	parser.add_argument('input_file', type=fileexists, help='Input File Location EX: /Desktop/Somewhere/input.txt')
	parser.add_argument('-l', '--log-output',  default=False, action='store_true', help='Log output to json file')
	parser.add_argument('-v', '--version', help='Version', action='store_true')
	parser.add_argument('-c', '--config', help='Version', action='store_true')
	args = parser.parse_args()
	
	if args.config:
		config = cfgsaver.get_from_cmd(pkg_name, config_keys)
		if config == None:
			print("Cound't read config values, please start the program again using --config parameter")
		return

	if config == None or config['api_key'] == "":
		a = """VirusTotal API key is empty. To obtain an API Key:

[1] Register an account on https://www.virustotal.com if you haven't. 
[2] Sign in and get your API Key from community profile.
[3] Enter configuration values below.

(Refer this link for more help: https://www.virustotal.com/en/documentation/public-api/)"""

		print(a)
		config = cfgsaver.get_from_cmd(pkg_name, config_keys)
		if config == None:
			print("Cound't read config values, please start the program again using --config parameter")
			return
		print("")
	#calculate hash of file
	print("calculating sha1 hash...")
	hash = hashlib.sha1()
	with open(args.input_file,'rb') as fp:
		for chunk in iter(lambda: fp.read(4096), b""):
			hash.update(chunk)
	strhash = hash.hexdigest()
	print("done. sending scan request...\n")
	scan(strhash.strip(), args.log_output) #args.verbose
	print("done")

# execute the program
if __name__ == '__main__':
	main()
