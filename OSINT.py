# Import Statements
import json
import argparse
import requests
import re
import os
import sys

# Import Report Builders from second Page
from Report import verbose_outfile
from Report import write_outfile
from Report import write_hashfile
from Report import verbose_hashfile
from Report import print_raw
from Report import print_raw_hash
from Report import print_raw_domain
from Report import domain_outfile
from Report import verbose_domain

def main():
  # ArgParse Options
  parser = argparse.ArgumentParser()
  parser.add_argument("-d", help="Domain address to Search", action='store', nargs='*')
  parser.add_argument("-e", help="Email address to Search Reputation", action='store', nargs='*')
  parser.add_argument("-f", "--file", help="File Hash to Check, Best return utilize SHA256 Hash.", action='store', nargs='*')
  parser.add_argument("-i", "--ip", help="IP Address for Search", action='store', nargs='*')
  parser.add_argument("-u", help="URL For Search and Scan", action='store',)
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

# API Key retrieve
with open('Config.json') as user_file:
  api_contents = user_file.read()

api_keys = json.loads(api_contents)

# API Keys By site
Virustotal = api_keys["Virus Total"]
AbuseIPDB = api_keys["AbuseIPDB"]
GreyNoise = api_keys["GreyNoise"]
HybridAnalysis = api_keys["Hybrid Analysis"]


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
    verbose_outfile(arg, vtiphist, ipdbhist, greyhist)
  else:
    write_outfile(arg, vtiphist, ipdbhist, greyhist)

# Grab and report on File Hash Reputation
def filerep(arg, hashsearch, raw, verbose):
  url = f'https://www.virustotal.com/api/v3/files/{arg}'
  headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
    }
  vt_hashresponse = requests.get(url, headers=headers)

  haurl = f'https://www.hybrid-analysis.com/api/v2/overview/{arg}'
  haheaders = {
    'accept': 'application/json',
    'api-key': f'{HybridAnalysis}'
  }
  ha_hashresponse = requests.get(url=haurl, headers=haheaders)

  # Circul Requires searches Separated by Hash Type
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
  url = f"https://www.virustotal.com/api/v3/domains/{arg}"
  headers = {
    "accept": "application/json",
    "x-apikey": f"{Virustotal}"
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

# Run Domain Check Loop
def domainloop(args):
  raw = args.r
  verbose = args.v
  for arg in args.d:
    domain_check(arg, raw, verbose)

# Confirm IP format and Start IP History Loop
def iphistloop(args):
  ipv4_pattern = r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
  raw = args.r
  verbose = args.v
  #This doesn't completely filter out values over 255.255.255.255 but catches letters and blank/missing fields
  for arg in args.ip:
    if re.match(ipv4_pattern, arg, re.ASCII):
      IP_Hist(arg, raw, verbose)
    else:
      print("Recheck IP address for formatting and values below 255.255.255.255")

# Grab Hash Argument and run Hash Check loop
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