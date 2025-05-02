# Import Statements
import json
import argparse
import requests
import re
import sys
import time
import socket

# Import Report Builders from Report.py
from Report import verbose_outfile
from Report import write_outfile
from Report import write_hashfile
from Report import verbose_hashfile
from Report import print_raw
from Report import print_raw_hash
from Report import print_raw_domain
from Report import print_raw_urlscan
from Report import domain_outfile
from Report import verbose_domain
from Report import write_urlscan
from Report import verbose_urlscan

def main():
  # ArgParse Options
  parser = argparse.ArgumentParser()
  parser.add_argument("-d", help="Domain address to Search", action='store', nargs='*')
  parser.add_argument("-e", help="Email address to Search Reputation", action='store', nargs='*')
  parser.add_argument("-f", "--file", help="File Hash to Check, Best return utilize SHA256 Hash.", action='store', nargs='*')
  parser.add_argument("-i", "--ip", help="IP Address for Search", action='store', nargs='*')
  parser.add_argument("-u", help="URL For Scan with UrlScan.io", action='store', nargs='*')
  parser.add_argument("-r", help='Raw Data output to Individual files', action='store_true')
  parser.add_argument("-v", help='Add Verbose return Information', action='store_true')
  
  args = parser.parse_args()

  if len(sys.argv) == 1:
    print("No Arguments Provided try running with '-h' to get help information")

  # Loop Through multiple Arguments and execute Functions Associated
  args2 = vars(args)
  for var, input in args2.items():
    if (input != None) & (var == 'ip'):
      print(f"IP Address(s) Provided: {args.ip}")
      iphistloop(args)
    elif (input != None) & (var == 'file'):
      print(f"File Hash Provided: {args.file}")
      hashloop(args)
    elif (input != None) & (var == 'd'):
      print(f"Domain Present: {input}")
      domainloop(args)
    elif (input != None) & (var == 'e'):
      print(f"Email Present: {input}")
    elif (input != None) & (var == 'u'):
      print(f"URL Present: {input}")
      scan_loop(args)

# API Key retrieve
with open('Config.json') as user_file:
  api_contents = user_file.read()

api_keys = json.loads(api_contents)

# API Keys By site
Virustotal = api_keys["Virus Total"]
AbuseIPDB = api_keys["AbuseIPDB"]
GreyNoise = api_keys["GreyNoise"]
HybridAnalysis = api_keys["Hybrid Analysis"]
UrlScan = api_keys["UrlScan"]


def IP_Hist(arg, raw, verbose):
  #Virus Total API Request
  vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{arg}'
  vt_headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
  }
  vtresponse = requests.get(vt_url, headers=vt_headers)
  vtiphist = json.loads(vtresponse.text)

  #AbuseIPDB API Request
  ipdb_url = 'https://api.abuseipdb.com/api/v2/check'
  querystring = {
    'ipAddress': f'{arg}',
    'maxAgeInDays': '90'
  }
  ipdb_headers = {
    'Accept': 'application/json',
    'Key': f'{AbuseIPDB}'
  }
  ipdb_response = requests.request(method='GET', url=ipdb_url, headers=ipdb_headers, params=querystring)
  ipdbhist = json.loads(ipdb_response.content)
   
  #Grey Noise API IP Lookup
  grey_url = f'https://api.greynoise.io/v3/community/{arg}'
  grey_headers = {
    'accept': 'application/json',
    'key': f'{GreyNoise}'
  }
  grey_response = requests.get(grey_url, headers=grey_headers)
  greyhist = json.loads(grey_response.text)

  #Call Output File Function including handles for Verbose and Raw Output
  if raw == True:
    print("Printing Raw Outputs to files")
    print_raw(arg, vtiphist, ipdbhist)
  elif verbose == True:
    print("Print Verbose Output File")
    verbose_outfile(arg, vtiphist, ipdbhist, grey_response)
  else:
    write_outfile(arg, vtiphist, ipdbhist, grey_response)

#Grab and report on File Hash Reputation
def filerep(arg, hashsearch, raw, verbose):
  #VirusTotal API
  url = f'https://www.virustotal.com/api/v3/files/{arg}'
  headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
    }
  vt_hashresponse = requests.get(url, headers=headers)

  #Hybrid Analysis API
  haurl = f'https://www.hybrid-analysis.com/api/v2/overview/{arg}'
  haheaders = {
    'accept': 'application/json',
    'api-key': f'{HybridAnalysis}'
  }
  ha_hashresponse = requests.get(url=haurl, headers=haheaders)

  #Circul Requires searches Separated by Hash Type
  if hashsearch == 'md5':
    url = f'https://hashlookup.circl.lu/lookup/md5/{arg}'
    headers = {
      'accept': 'application/json',
      }
    circul_response = requests.get(url, headers=headers)
  elif hashsearch == 'sha1':
    url = f'https://hashlookup.circl.lu/lookup/sha1/{arg}'
    headers = {
      'accept': 'application/json',
      }
    circul_response = requests.get(url, headers=headers)
  elif hashsearch == 'sha256':
    url = f'https://hashlookup.circl.lu/lookup/sha256/{arg}'
    headers = {
      'accept': 'application/json',
      }
    circul_response = requests.get(url, headers=headers)

  if raw == True:
    print("Output Raw Json to files")
    vthashcon = json.loads(vt_hashresponse.content)
    circulhashcon = json.loads(circul_response.content)
    hahashcon = json.loads(ha_hashresponse.content)
    print_raw_hash(vthashcon, circulhashcon, hahashcon)
  elif verbose == True:
    print("Print Verbose Output File")
    verbose_hashfile(arg, vt_hashresponse, circul_response, ha_hashresponse)
  else:
    write_hashfile(arg, vt_hashresponse, circul_response, ha_hashresponse)

def domain_check(arg, raw, verbose):
  #Virus Total API Check
  url = f'https://www.virustotal.com/api/v3/domains/{arg}'
  headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
    }
  vt_domainres = requests.get(url, headers=headers)

  if raw == True:
    print("Print Raw Output File")
    print_raw_domain(arg, vt_domainres)
  elif verbose == True:
    print("Printing Verbose Outfile")
    verbose_domain(arg, vt_domainres)
  else:
    print("Printing Domain Output file")
    domain_outfile(arg, vt_domainres)

#UrlScan.io Request and Report
def url_scan(arg, raw, verbose):
  scan_url = 'https://urlscan.io/api/v1/scan/'
  headers = {
    'API-Key': f'{UrlScan}',
    'Content-Type':'application/json'
    }
  data = {
    'url': f'{arg}',
    'visibility': 'public'
    }
  response = requests.post(scan_url, headers=headers, data=json.dumps(data))
  response_js = json.loads(response.text)
  uuid = response_js["uuid"]
  print(uuid)
  print(f"Wait 30s then check for completed scan result of uuid: {uuid}")
  time.sleep(30)
  re_scan(uuid, raw, verbose)

#Run UrlScan Loop
def scan_loop(args):
  raw = args.r
  verbose = args.v
  for arg in args.u:
    url_scan(arg, raw, verbose)

#Run Return UrlScan Check
def re_scan(uuid, raw, verbose):
  re_url = f'https://urlscan.io/api/v1/result/{uuid}'
  headers = {
    'API-Key': f'{UrlScan}',
    'Content-Type':'application/json'
    }
  re_response = requests.get(re_url, headers=headers)
  recheck_loop(uuid, re_response, raw, verbose)
  
#Build Recheck loop for waiting for UrlScan.io
def recheck_loop(uuid, re_response, raw, verbose):
  if re_response.status_code == 404:
    print(f"Scan of uuid '{uuid}' is not finished, wait 10s repeat query")
    time.sleep(10)
    re_scan(uuid)
  elif re_response.status_code == 410:
    print(f"Scan of uuid '{uuid}' has been deleted, re-run CLI command and confirm url provided")
  elif re_response.status_code == 200:
    print("Scan Complete Printing Output Information Now.")
    if raw == True:
      print("Printing Raw Scan Output")
      print_raw_urlscan(re_response)
    elif verbose == True:
      print("Print Verbose file Output")
      verbose_urlscan(uuid, re_response)
    else:
      print("Printing Standard Output with Verdict information")
      write_urlscan(uuid, re_response)

#Run Domain Check Loop
def domainloop(args):
  raw = args.r
  verbose = args.v
  for arg in args.d:
    domain_check(arg, raw, verbose)

#Confirm IP format and Start IP History Loop
def valid_ip(arg):
  try:
    socket.inet_aton(arg)
    return True
  except:
    return False

def iphistloop(args):
  raw = args.r
  verbose = args.v
  for arg in args.ip:
    if valid_ip(arg) == True:
      IP_Hist(arg, raw, verbose)
    elif valid_ip(arg) == False:
      print("Recheck IP address for formatting and values below 255.255.255.255")
    else:
      print("Something else Broke")

#Grab Hash Argument and run Hash Check loop
def hashloop(args):
  raw = args.r
  verbose = args.v
  hashtype = input("""Please Choose the Hash Algorithm for Search:
1. MD5
2. SHA1
3. SHA256
""")
  for arg in args.file:
    if hashtype == '1':
      hashsearch = 'md5'
      filerep(arg, hashsearch, raw, verbose)
    elif hashtype == '2':
      hashsearch = 'sha1'
      filerep(arg, hashsearch, raw, verbose)
    elif hashtype == '3':
      hashsearch = 'sha256'
      filerep(arg, hashsearch, raw, verbose)
    else:
      print("The only currently supported values are 1, 2, 3. Please re-run the program.")

if __name__ == "__main__":
  main()