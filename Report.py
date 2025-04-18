import json
import os

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
    home_dir = os.path.expanduser("~")
    outputfile = f"{arg}-verbose.txt"
    output = os.path.join(home_dir, outputfile)
    outfile = open(output, 'w')
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
    home_dir = os.path.expanduser("~")
    outputfile = f"{arg}-Standard.txt"
    output = os.path.join(home_dir, outputfile)
    outfile = open(output, 'w')
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

def verbose_hashfile(arg, vt_hashresponse, circul_response, ha_hashresponse):
    print("Building Verbose Hash Information File")
    vthash = json.loads(vt_hashresponse.text)
    circulhash = json.loads(circul_response.text)
    hahash = json.loads(ha_hashresponse.text)
    print(circulhash)
    votes = vthash["data"]["attributes"]["total_votes"]
    names = vthash["data"]["attributes"]["names"]
    reputation = vthash["data"]["attributes"]["reputation"]
    last_analysis = vthash["data"]["attributes"]["last_analysis_stats"]
    if circul_response.status_code == 200:
        trust = circulhash["hashlookup:trust"]
    else:
        trust = 'Not Found'
    if ha_hashresponse.status_code == 200:
        threatscore = hahash["threat_score"]
        verdict = hahash["verdict"]
        hatype = hahash["type"]
        tag = hahash["tags"]
        family = hahash["vx_family"]
    else:
        threatscore = 'Not Found'
        verdict = 'Not Found'
        hatype = 'Not Found'
        tag = 'Not Found'
        family = 'Not Found'
    home_dir = os.path.expanduser("~")
    outputfile = "Hash-Verbose.txt"
    output = os.path.join(home_dir, outputfile)
    outfile = open(output, 'w')
    outfile.write(f"""Report from Virus Total and Circul.lu APIs:
-------------HEADLINE INFORMATION-------------------
Hash searched: {arg}
Total Votes from Virus Total: {votes}
Cicul HashLookup Trust Value: {trust}
Hybrid Analysis Threat Score: {threatscore}
--------------Additional Data-----------------------
Virus Total Reputation:
{reputation}
Hybrid Analysis Verdict:
{verdict}
Virus Total Last Analysis: {last_analysis}

Hybrid Analysis Additional Identifiers:
{hatype}
{tag}
{family}

Circul HashLookup Trust Breakdown:
Scale: 0-100
< 50 = Less trust in the file
50 = No Opinion of the File
> 50 = Appears in Multiple sources and has an improved Trust
""")

def write_hashfile(arg,  vt_hashresponse, circul_response, ha_hashresponse):
    print("Building Hash Information File")
    vthash = json.loads(vt_hashresponse.text)
    circulhash = json.loads(circul_response.text)
    hahash = json.loads(ha_hashresponse.text)
    votes = vthash["data"]["attributes"]["total_votes"]
    names = vthash["data"]["attributes"]["names"]
    reputation = vthash["data"]["attributes"]["reputation"]
    last_analysis = vthash["data"]["attributes"]["last_analysis_stats"]
    if circul_response.status_code == 200:
        trust = circulhash["hashlookup:trust"]
    else:
        trust = 'Not Found'
    if ha_hashresponse.status_code == 200:
        threatscore = hahash["threat_score"]
        verdict = hahash["verdict"]
    else:
        threatscore = 'Not Found'
        verdict = 'Not Found'
    home_dir = os.path.expanduser("~")
    outputfile = "Hash-Standard.txt"
    output = os.path.join(home_dir, outputfile)
    outfile = open(output, 'w')
    outfile.write(f"""Report from Virus Total and Circul.lu APIs:
-------------HEADLINE INFORMATION-------------------
Hash searched: {arg}
Total Votes from Virus Total: {votes}
Cicul HashLookup Trust Value: {trust}
Hybrid Analysis Threat Score: {threatscore}
--------------Additional Data-----------------------
Virus Total Reputation:
{reputation}
Hybrid Analysis Verdict:
{verdict}
Virus Total Last Analysis: {last_analysis}

Circul HashLookup Trust Breakdown:
Scale: 0-100
< 50 = Less trust in the file
50 = No Opinion of the File
> 50 = Appears in Multiple sources and has an improved Trust

Circul Associated Filename:
""")
