##
# vtscan.py - Utility to scan for malicious files using the VirusTotal API
#
# @author Prahlad Yeri <prahladyeri@yahoo.com>
# @license MIT
import requests
import argparse
import os, sys
import time
import hashlib
import json
from vtscan import __title__, __description__, __version__

pkg_name = "vtscan"
cfg = {"api_key": ""} #default
cache = {"data": {}}

#@todo: move this to a common util library
CSI = '\033['

class Color():
    BLACK           = CSI + '30m'
    RED             = CSI + '31m'
    GREEN           = CSI + '32m'
    YELLOW          = CSI + '33m'
    BLUE            = CSI + '34m'
    MAGENTA         = CSI + '35m'
    CYAN            = CSI + '36m'
    WHITE           = CSI + '37m'
    RESET           = CSI + '39m'

clr = Color()


def get_config_dir():
    #return os.path.join(os.path.expanduser("~/.config/"), pkg_name+'-settings.json')
    tpath = os.path.expanduser(f"~/.config/{pkg_name}/")
    tpath = tpath.replace(os.sep, '/')
    if not os.path.exists(tpath):
        os.makedirs(tpath)
    return tpath

def load_config():
    global cfg
    #tpath = sysconfig.get_path('purelib') + os.sep + "siterank"
    fname = get_config_dir() + 'settings.json'
    if not os.path.exists(fname):
        open(fname, 'w').write(json.dumps(cfg))
    else:
        cfg = json.loads( open(fname, 'r').read())
    return
    
def load_cache():
    global cache
    fname = get_config_dir() + "cache.json"
    if not os.path.exists(fname):
        open(fname, 'w').write(json.dumps(cache))
    else:
        cache = json.loads(open(fname).read())
    return
    
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
        #if filepath == None: return ""
        if os.path.isfile(filepath):
            return filepath
        else:
            print("There is no file at:" + filepath)
            exit()
    except Exception as ex:
            print(ex)

def print_scan(data):
    #print ("permalink: ", data.get('permalink'))
    print("hash: %s" % data.get('sha1'))
    positives = int(data.get('positives'))
    total = int(data.get('total'))
    # mcafee = str(data.get('report'))
    print("Number of positives: %d (out of %d scanners applied)" % (positives, total))
    print("verbose_msg: %s" % data.get('verbose_msg'))
    scans = data.get('scans')
    for key in scans:
        if scans[key]['detected']: 
            print(clr.RED + key, "v", scans[key]['version'], ": ", str(scans[key]['result']), clr.RESET)
    if positives == 0:
        print(data.get('sha1') + ' is ' + clr.GREEN + 'likely good.' + clr.RESET)
    else:
        print(data.get('sha1') + ' is ' + clr.RED + 'likely malicious.' + clr.RESET)

def scan(hash, log_output=False, is_file=False):
    global cache
    if cfg['api_key'] == "":
        raise Exception("api key is missing")
        return

    #print("verbose output: ",verbose)
    params, files= {}, {}
    if is_file: # hash is actually the filename
        params = {'apikey': cfg['api_key']} #'allinfo': verbose
        files = {'file': (os.path.split(hash)[1], open(hash, 'rb'))}
        print("Uploading file...")
        resp = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', params=params, files=files)
        if resp.status_code != 200:
            print(f"Upload failed. Status: {resp.status_code}, Body: {resp.text}")
            return        
        try:
            json_response = resp.json()
        except ValueError:
            print("Response was not valid JSON. Raw content:")
            print(resp.text)
            return            
        if 'sha256' in json_response.keys():
            print("File uploaded. Performing scan...")
            scan(json_response.get('sha256'), log_output, False)
    else:
        params = {'apikey': cfg['api_key'], 'resource': hash, } #'allinfo': verbose
        resp = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        if resp.status_code == 204:
            print("Rate limit exceeded (HTTP 204). Try again after a minute.")
            return
        elif resp.status_code != 200:
            print(f"Request failed. Status: {resp.status_code}, Body: {resp.text}")
            return        
        try:
            json_response = resp.json()
        except ValueError:
            print("Response was not valid JSON. Raw content:")
            print(resp.text)
            return        
        if json_response['response_code'] > 0 and hash not in cache['data'].keys():
            cache['data'][hash] = dict(json_response)
            open(get_config_dir() + "cache.json", 'w').write(json.dumps(cache))
        if log_output:
            ss = json.dumps(json_response, indent=4)
            open('output.json','w').write(ss)
            print("Logged output to output.json")
        response = int(json_response.get('response_code'))
        if response == 0:
            print (clr.YELLOW + 'Not found in VT Database' + clr.RESET)
            return 'not found'
        elif response == 1:
            print ('Found in VT Database')
            print_scan(json_response)
        else:
            print (hash + ' could not be searched. Please try again later.')

def main():
    #print('DEBUG', set(['-v', '--version']), sys.argv)
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=fileexists, help='Input File Location EX: /Desktop/Somewhere/input.txt', nargs="?")
    parser.add_argument('-l', '--log-output',  default=False, action='store_true', help='Log output to output.json file')
    parser.add_argument('-v', '--version', help='Version', action='store_true')
    args = parser.parse_args()
    
    if args.version:
        print( "%s version %s" % (__title__, __version__) )
        return
    
    load_config()
    if cfg['api_key'] == "":
        a = """VirusTotal API key is empty. To obtain an API Key:

[1] Register an account on https://www.virustotal.com/ if you haven't. 
[2] Sign in and get your API Key from community profile.
[3] Enter configuration values in %s.
[4] Restart this program.

(Refer this link for more help: https://www.virustotal.com/en/documentation/public-api/)"""

        print(a % (get_config_dir()+"settings.json"))
        return
    load_cache()
    #check if filename is valid
    if args.input_file == None:
        print("Filename can't be empty")
        return
    #calculate hash of file
    print("calculating sha1 hash...")
    hash = hashlib.sha1()
    with open(args.input_file,'rb') as fp:
        for chunk in iter(lambda: fp.read(4096), b""):
            hash.update(chunk)
    strhash = hash.hexdigest()
    print("finding hash in local cache..")
    result = False
    if strhash in cache['data'].keys():
        print("found in cache..\n")
        print_scan(cache['data'][strhash])
    else:
        print("not found in cache, sending scan request..\n")
        result = scan(strhash.strip(), args.log_output, False) #args.verbose
    if result == 'not found':
        ss = input("Do you want to upload this file to vtscan database? (Y/n):")
        if ss.lower() == 'y': # @todo: make sure the file is less than 32MB
            result = scan(args.input_file, args.log_output, True)

# execute the program
if __name__ == '__main__':
    main()
