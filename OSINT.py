# Import Statements
import json
import argparse
import requests
import re
import os
import sys

def main():
  # ArgParse Options
  parser = argparse.ArgumentParser()
  parser.add_argument("-d", help="Domain address to Search", action='store', nargs='*')
  parser.add_argument("-e", help="Email address to Search Reputation", action='store', nargs='*')
  parser.add_argument("-f", "--file", help="File Hash to Check", action='store', nargs='*')
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

def verbose_outfile(arg, vtiphist, ipdbhist, greyhist):
    print("Building Verbose IP History File")
    votes = vtiphist["data"]["attributes"]["total_votes"]
    whois = vtiphist["data"]["attributes"]["whois"]
    country = vtiphist["data"]["attributes"]["country"]
    ca_information = vtiphist["data"]["attributes"]["last_https_certificate"]["extensions"]["ca_information_access"]
    cert_issuer = vtiphist["data"]["attributes"]["last_https_certificate"]["issuer"]
    cert_subject = vtiphist["data"]["attributes"]["last_https_certificate"]["subject"]
    valid  = vtiphist["data"]["attributes"]["last_https_certificate"]["validity"]
    confidence = ipdbhist["data"]["abuseConfidenceScore"]
    country2 = ipdbhist["data"]["countryCode"]
    usage = ipdbhist["data"]["usageType"]
    whitelist = ipdbhist["data"]["isWhitelisted"]
    domain = ipdbhist["data"]["domain"]
    classification = greyhist["classification"]
    outfile = open(f"{arg}.txt", 'w')
    outfile.write(f"""Report from Multiple sources:
-------------HEADLINE INFORMATION-------------------
Total Votes from Virus Total: {votes}
AbuseIPDB Abuse Conifdence Score: {confidence}
*Abuse IPDB WhiteList Status: {whitelist}
Grey Noise Classification: {classification}
--------------Additional Data-----------------------
Who Is Data From Virus Total:
{whois}

Possible Country Attribution:
Virus Total Country: {country}
AbuseIPDB Country: {country2}

Certificate information:
{ca_information}
Cert Issuer:
{cert_issuer}
Cert Subject: {cert_subject}
Abuse IPDB usage type: {usage}
Abuse IPDB Domain: {domain}
Certificate Valid Dates:
{valid}
""")

def write_outfile(arg, vtiphist, ipdbhist, greyhist):
    print("Building IP History File")
    votes = vtiphist["data"]["attributes"]["total_votes"]
    whois = vtiphist["data"]["attributes"]["whois"]
    country = vtiphist["data"]["attributes"]["country"]
    ca_information = vtiphist["data"]["attributes"]["last_https_certificate"]["extensions"]["ca_information_access"]
    valid  = vtiphist["data"]["attributes"]["last_https_certificate"]["validity"]
    confidence = ipdbhist["data"]["abuseConfidenceScore"]
    country2 = ipdbhist["data"]["countryCode"]
    classification = greyhist["classification"]
    outfile = open(f"{arg}.txt", 'w')
    outfile.write(f"""Report from Multiple sources:
-------------HEADLINE INFORMATION-------------------
Total Votes from Virus Total: {votes}
AbuseIPDB Abuse Conifdence Score: {confidence}
Grey Noise Classification: {classification}
--------------Additional Data-----------------------
Who Is Data From Virus Total:
{whois}

Possible Country Attribution:
Virus Total Country: {country}
AbuseIPDB Country: {country2}

Certificate information:
{ca_information}
Certificate Valid Dates:
{valid}
""")

def print_raw(arg, vtiphist, ipdbhist):
  home_dir = os.path.expanduser("~")
  raw_vt = f"raw-{arg}-VirusTotal.json"
  file_vt = os.path.join(home_dir, raw_vt)
  raw_ipdb = f"raw-{arg}-AbuseIPDB.json"
  file_ipdb = os.path.join(home_dir, raw_ipdb)
  with open(file_vt, 'w') as file:
    print(vtiphist)
    file.close
    print(f"Virus Total IP Information Json File stored at {file_vt}")
  with open(file_ipdb, 'w') as file:
    print(ipdbhist)
    file.close
    print(f"AbuseIPDB IP Information Json File stored at {file_ipdb}")

def IP_Hist(arg, raw, verbose):
  #Virus Total API Request
  vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{arg}'
  vt_headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
  }
  vtresponse = requests.get(vt_url, headers=vt_headers)
  # Grab "important" Fields from json return
  vtiphist = json.loads(vtresponse.text)
  #build_filevt(arg, vtiphist)

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
  # Formatted output
  ipdbhist = json.loads(ipdb_response.content)
   
  #Grey Noise API IP Lookup
  grey_url = f'https://api.greynoise.io/v3/community/{arg}'
  grey_headers = {
    'accept': 'application/json',
    'key': f'{GreyNoise}'
  }
  grey_response = requests.get(grey_url, headers=grey_headers)

  greyhist = json.loads(grey_response.text)

  #Call Output File Function
  if raw == True:
    print("Printing Raw Outputs to files")
    print_raw(arg, vtiphist, ipdbhist)
  elif verbose == True:
    print("Print Verbose Output File")
    verbose_outfile(arg, vtiphist, ipdbhist, greyhist)
  else:
    write_outfile(arg, vtiphist, ipdbhist, greyhist)

def filerep(arg, hashsearch):
  url = f'https://www.virustotal.com/api/v3/files/{arg}'
  headers = {
    'accept': 'application/json',
    'x-apikey': f'{Virustotal}'
    }
  response = requests.get(url, headers=headers)
  print(response.text)

# Confirm IP format and Start IP History Loop
def iphistloop(args):
  print('Loop executed')
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
  hashtype = input("""Please Choose the Hash Algorithm for Search:
1. MD5
2. SHA256
3. SHA 512
""")
  for val in args.file:
    if hashtype == '1':
      hashsearch = 'md5'
      filerep(val, hashsearch)
    elif hashtype == '2':
      hashsearch = 'sha256'
      filerep(val, hashsearch)
    elif hashtype == '3':
      hashsearch = 'sha512'
      filerep(val, hashsearch)
    else:
      print("The only currently supported values are 1, 2, 3. Please re-run the program.")

if __name__ == "__main__":
  main()