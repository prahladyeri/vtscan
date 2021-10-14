##
# VTScan - Utility to scan for malicious files using the VirusTotal API
#
# @author Prahlad Yeri <prahladyeri@yahoo.com>
# @translator Nhat Hung Tran <nhathungtran2011@gmail.com>
# @license MIT
# @modified 2021-10-14
#
import requests
import argparse
import os, sys, platform
import time
import hashlib
import json
import win_unicode_console # Unicode in Windows console
from cfgsaver import cfgsaver
from vtscan import __title__, __description__, __version__
from colorama import Fore, Style

pkg_name = "vtscan"
config_keys = ['api_key']
config = cfgsaver.get(pkg_name)

if platform.system() == "Windows"
  if win_unicode_console.console.running_console is not None:
    win_unicode_console.console.disable() # Disables Unicode if the console is closed.
  else:
    win_unicode_console.console.enable() # Enables Unicode in Windows console.

def checkkey(kee):
    try:
        if len(kee) == 64:
            return kee
        else:
            print("Có điều gì đó sai với khóa của bạn. Không phải 64 ký tự chứa chữ và số.")
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
            print("Đầu vào mã có vẻ không hợp lệ.")
            exit()
    except e as Exception:
            print(e)
            
def fileexists(filepath):
    try:
        #if filepath == None: return ""
        if os.path.isfile(filepath):
            return filepath
        else:
            print("Không có tệp nào ở:" + filepath)
            exit()
    except Exception as ex:
            print(ex)


def scan(hash, log_output=False, is_file=False):
    if 'api_key' not in config or config['api_key'] == "":
        raise Exception("khóa API bị thiếu")
        return

    #print("verbose output: ",verbose)
    params, files= {}, {}
    if is_file: # hash is actually the filename
        params = {'apikey': config['api_key']} #'allinfo': verbose
        files = {'file': (os.path.split(hash)[1], open(hash, 'rb'))}
        print("Đang tải tệp lên...")
        url = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', params=params, files=files)
        json_response = url.json()
        #print("json_response:", json_response)
        if 'sha256' in json_response.keys():
            print("Đang quét. Nếu quét tệp không thành công, xin vui lòng khởi động lại ứng dụng.")
            scan(json_response.get('sha256'), log_output, False)
        return
    else:
        params = {'apikey': config['api_key'], 'resource': hash, } #'allinfo': verbose
        url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    if log_output:
        ss = json.dumps(json_response, indent=4)
        open('output.json','w').write(ss)
        print("Đầu ra đã được ghi vào output.json")
    response = int(json_response.get('response_code'))
    if response == 0:
        print (Fore.YELLOW + 'không có trong cở sở dữ liệu VirusTotal' + Fore.RESET)
        return "not_found"
    elif response == 1:
        print ('Đã tìm thấy trong cở sở dữ liệu VirusTotal!')
        print ("Liên kết vĩnh viễn: ", json_response.get('permalink'))
        positives = int(json_response.get('positives'))
        total = int(json_response.get('total'))
        # mcafee = str(json_response.get('report'))
        print("Number of positives: %d (out of %d scanners applied)" % (positives, total))
        #print("sha1: %s" % json_response.get('sha256'))
        print("verbose_msg: %s" % json_response.get('verbose_msg'))
        if positives == 0:
            print(Fore.GREEN + hash + ' không phải là vi-rút' + Fore.RESET)
        else:
            print(Fore.RED + hash + ' là vi-rút' + Fore.RESET)
            print("")
        scans = json_response.get('scans')
        for key in scans:
            if scans[key]['detected']: 
                print(Fore.RED + key, "v", scans[key]['version'], ": ", str(scans[key]['result']), Fore.RESET)
    else:
        print ('Không tìm thấy ' + hash + ' trong máy chủ của VirusTotal. Vui lòng thử lại sau.')
    print("")

def main():
    global config
    #print('DEBUG', set(['-v', '--version']), sys.argv)
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=fileexists, help='Ví dụ về vị trí tệp đầu vào: /Desktop/input.zip', nargs="?")
    parser.add_argument('-l', '--log-output',  default=False, action='store_true', help='Ghi đầu ra vào tệp output.json')
    parser.add_argument('-v', '--version', help='Version', action='store_true')
    parser.add_argument('-c', '--config', help='Version', action='store_true')
    args = parser.parse_args()
    
    if args.version:
        print( "%s phiên bản %s" % (__title__, __version__) )
        return
    elif args.config:
        config = cfgsaver.get_from_cmd(pkg_name, config_keys)
        if config == None:
            print("Không đọc được giá trị cấu hình. Vui lòng khởi động lại ứng dụng với lệnh --config")
        return

    if config == None or config['api_key'] == "":
        a = """Khóa API VirusTotal trống. Để có được Khóa API thì bạn phải...
[1] Đăng ký tài khoản trên https://www.virustotal.com (nếu bạn chưa đăng ký).
[2] Đăng nhập và nhận khóa API của bạn từ tài khoản VirusTotal.
[3] Nhập các giá trị cấu hình bên dưới.
(Tham khảo liên kết này để được trợ giúp thêm: https://www.virustotal.com/en/documentation/public-api/)"""

        print(a)
        config = cfgsaver.get_from_cmd(pkg_name, config_keys)
        if config == None:
            print("Không đọc được giá trị cấu hình. Vui lòng khởi động lại ứng dụng với lệnh --config")
            return
        print("")
    #check if filename is valid
    if args.input_file == None:
        print("Tên tệp không được để trống.")
        return
    #calculate hash of file
    print("Đang tính toán mã SHA1...")
    hash = hashlib.sha1()
    with open(args.input_file,'rb') as fp:
        for chunk in iter(lambda: fp.read(4096), b""):
            hash.update(chunk)
    strhash = hash.hexdigest()
    print("Đã tải tệp lên thành công. Đang gửi yêu cầu quét...\n")
    result = scan(strhash.strip(), args.log_output, False) #args.verbose
    if result == 'not_found':
        ss = input("Bạn có muốn tải tệp này lên cơ sở dữ liệu vtscan? (y/n):")
        if ss.lower() == 'y': # @todo: make sure the file is less than 32MB
            result = scan(args.input_file, args.log_output, True)
    print("Đã xong!")

# execute the program
if __name__ == '__main__':
    main()
