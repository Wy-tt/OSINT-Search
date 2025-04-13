Build Automated Command-Line OSINT Search Utility to report on IP/Domains/File Hashes found in IOC's.

-Initial commit with functionality to grab and report of aspects from Virus Total IP Search

OSINT V1 Goals:
1. Finalized V1 intends to include:
2. IP History File from sources:
  -AbuseIPDB API,
  -Virus Total API,
  -Grey Noise API,
  -Sans Internet Storm Center API,
3. Domain Information from Sources:
  -Virus Total API,
4. File Hash Report
  -Virus Total API,
  -Hashlookup CIRCL_API,
  -MWDB Core API,
5. Email Reputation from Sources:
  -EmailRep API,
6. URL Check/Scan from
  -Dump from URLHaus,
  -URLScan.io,

---Integrations With SHODAN search will be included as testing is concluded with the above

Each of the Above steps will generate a clear report with summary information on the top of the page followed by Detailed information by source further down the page.
