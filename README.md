Automated Command-Line OSINT Search Utility to report on IP/Domains/File Hashes found in Potential IOC's.

OSINT V1 Completed List:
1. IP History File from sources:
  -AbuseIPDB API,
  -Virus Total API,
  -Grey Noise API,
2. Domain Information from Sources:
  -Virus Total API,
3. File Hash Report
  -Virus Total API,
  -Hashlookup CIRCL_API,
  -Hybrid Analysis API
4. URL Scan from
  -URLScan.io,
    -Send URL for Scan,
    -Check Return and print return verdict from UrlScan.io
5. Act on Additional Parameters:
  -Verbose Switch
  -Raw Switch

OSINT v1 remaining Goal:
1. Email Reputation from Source:
  -EmailRep API,

Initial Setup for use each user will need to gather the Requisit API Keys.
This will include creating a file titled "Config.json" with the following format:

{
  "Virus Total": "Key_Value",
  "AbuseIPDB": "Key_Value",
  "GreyNoise": "Key_Value",
  "Hybrid Analysis": "Key_Value"
}

***Each of these entities has their own API Access Rules, each user is responsible for ensuring access is within those rules.
