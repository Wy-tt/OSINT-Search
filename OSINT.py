# Import Statements
import json
import argparse
import requests
import re

# API Key retrieve
with open('Config.json') as user_file:
  api_contents = user_file.read()

api_keys = json.loads(api_contents)

# API Keys By site
Virustotal = api_keys["Virus Total"]
AbuseIPDB = api_keys["AbuseIPDB"]
GreyNoise = api_keys["GreyNoise"]

# ArgParse Options
parser = argparse.ArgumentParser()
parser.add_argument("-d", help="Domain address to Search", action='store', default='None')
parser.add_argument("-f", help="File Hash Check", action='store', default='None')
parser.add_argument("-i", "--ip", help="IP Address for Search", action='store', default='None', nargs='*')
parser.add_argument("-u", help="URL For Search and Scan", action='store', default='None')
parser.add_argument('-r', help='Raw Data output', action='store_true', default='None')
parser.add_argument('-v', help='Add Verbose return Information', action='store_true', default='None')
args = parser.parse_args()

print(args)

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
    outfile = open(f"{arg}.txt", 'a')
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
    outfile = open(f"{arg}.txt", 'a')
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

def IP_Hist(arg):
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
  if args.v == True:
    print("Print Verbose Output File")
    verbose_outfile(arg, vtiphist, ipdbhist, greyhist)
  else:
    write_outfile(arg, vtiphist, ipdbhist, greyhist)

# Confirm IP format and Build function trggers from Arguments
ipv4_pattern = r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
#This doesn't completely filter out values over 255.255.255.255 but catches letters and blank/missing fields
for arg in args.ip:
  print(arg)
  if re.match(ipv4_pattern, arg, re.ASCII):
    IP_Hist(arg)
  else:
     print("Recheck IP address for formatting and values below 255.255.255.255")