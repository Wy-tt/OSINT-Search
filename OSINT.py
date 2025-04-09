# Import Statements
import json
import argparse
import requests

# API Key retrieve
with open('Config.json') as user_file:
  file_contents = user_file.read()

parsed_json = json.loads(file_contents)

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

# API Keys By site
Virustotal = parsed_json["Virus Total"]
AbuseIPDB = parsed_json["AbuseIPDB"]

# Build Virus Total IP History File
def build_filevt(arg, vtiphist):
  print("Building Virus Total IP History File")
  votes = vtiphist["data"]["attributes"]["total_votes"]
  whois = vtiphist["data"]["attributes"]["whois"]
  country = vtiphist["data"]["attributes"]["country"]
  ca_information = vtiphist["data"]["attributes"]["last_https_certificate"]["extensions"]["ca_information_access"]
  valid = vtiphist["data"]["attributes"]["last_https_certificate"]["validity"]
  vt = open(f"{arg}.txt", 'a')
  vt.write(json.dumps(votes) + "\n")
  vt.write("Who is data: " + "\n")
  vt.write(whois + "\n")
  vt.write("Country Attribution: " + "\n")
  vt.write(country + "\n")
  vt.write("Certificate Issuer Information: " + "\n")
  vt.write(json.dumps(ca_information) + "\n")
  vt.write("Certificate Validity Information: " + "\n")
  vt.write(json.dumps(valid) + "\n")
  vt.close
  return(0)

def IP_Hist(arg):
   #Virus Total API Request
   url = f"https://www.virustotal.com/api/v3/ip_addresses/{arg}"
   headers = {
     "accept": "application/json",
     "x-apikey": f"{Virustotal}"
     }
   vtresponse = requests.get(url, headers=headers)
   # Grab "important" Fields from json return
   vtiphist = json.loads(vtresponse.text)
   build_filevt(arg, vtiphist)

   #AbuseIPDB API Request
   url = 'https://api.abuseipdb.com/api/v2/check'
   querystring = {
     'ipAddress': f'{arg}',
     'maxAgeInDays': '90'
     }
   headers = {
     'Accept': 'application/json',
     'Key': f'{AbuseIPDB}'
     }
   ipdb_response = requests.request(method='GET', url=url, headers=headers, params=querystring)
   # Formatted output
   ipdbhist = json.loads(ipdb_response.text)
   print(ipdbhist)


# Build function trggers from Arguments
for arg in args.ip:
  IP_Hist(arg)
  