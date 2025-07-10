import json
import unittest
import sys
import io
from unittest.mock import Mock, patch, MagicMock
from types import SimpleNamespace

#import functions from other pages to test
from OSINT import valid_ip
from OSINT import vt_ip_check
from OSINT import abuse_IPDB_check
from OSINT import grey_ip_check
from OSINT import vt_hashrep
from OSINT import ha_hashrep
from OSINT import hashloop
from OSINT import cir_hashrep
from scratch import url_scan
from scratch import re_scan

class TestFunctions(unittest.TestCase):
    def test_true_ip(self):
        self.assertEqual(valid_ip('100.100.100.100'), True)
        self.assertEqual(valid_ip('255.255.255.255'), True)

    def test_false_ip(self):
        self.assertEqual(valid_ip('265.0.0.0'), False)
        self.assertEqual(valid_ip('245.999.0.0'), False)

    @patch('builtins.input', return_value='1')
    def test_hashloop_md5(self, mocked_input):
        config = SimpleNamespace(file=None, r=False, v=False)
        input = hashloop(config)
        self.assertEqual(input, "md5")
        mocked_input.assert_called_once_with("""Please Choose the Hash Algorithm for Search:
1. MD5
2. SHA1
3. SHA256
""")
        
    @patch('builtins.input', return_value='2')
    def test_hashloop_sha1(self, mocked_input):
        config = SimpleNamespace(file=None, r=False, v=False)
        input = hashloop(config)
        self.assertEqual(input, "sha1")
        mocked_input.assert_called_once_with("""Please Choose the Hash Algorithm for Search:
1. MD5
2. SHA1
3. SHA256
""")
    
    @patch('builtins.input', return_value='3')
    def test_hashloop_sha256(self, mocked_input):
        config = SimpleNamespace(file=None, r=False, v=False)
        input = hashloop(config)
        self.assertEqual(input, "sha256")
        mocked_input.assert_called_once_with("""Please Choose the Hash Algorithm for Search:
1. MD5
2. SHA1
3. SHA256
""")

    @patch('requests.get')
    def test_vt_ip_check(self, mock_get):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        Virustotal = api_keys["Virus Total"]

        vt_headers = {
            'accept': 'application/json',
            'x-apikey': f'{Virustotal}'
            }
        mock_response = Mock()
        response_json = {"data": {"attributes": {"total_votes": "Test Successful", "whois": "whois check"}}}
        mock_response.json.return_value = response_json

        mock_get.return_value = mock_response
        ip_data = vt_ip_check('8.8.8.8')
        mock_get.assert_called_with("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers=vt_headers)
        self.assertEqual(ip_data, response_json)

    @patch('requests.get')
    def test_abuse_IPDB_check(self, mock_get):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        AbuseIPDB = api_keys["AbuseIPDB"]

        ipdb_url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': '8.8.8.8',
            'maxAgeInDays': '90'
            }
        ipdb_headers = {
            'Accept': 'application/json',
            'Key': f'{AbuseIPDB}'
            }
        mock_response = Mock()
        response_json = {"data": {"abuseconfidencescore": "test Success"}}
        mock_response.json.return_value = response_json
        mock_get.return_value = mock_response
        ab_data = abuse_IPDB_check('8.8.8.8')
        mock_get.assert_called_with(url=ipdb_url, headers=ipdb_headers, params=querystring)

    @patch('requests.get')
    def test_grey_ip_check(self, mock_get):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        GreyNoise = api_keys["GreyNoise"]
        grey_url = 'https://api.greynoise.io/v3/community/8.8.8.8'
        grey_headers = {
            'accept': 'application/json',
            'key': f'{GreyNoise}'
            }
        mock_response = Mock()
        response_json = {"classification": "test"}
        mock_response.json.return_value = response_json
        mock_get.return_value = mock_response
        grey_data = grey_ip_check('8.8.8.8')
        mock_get.assert_called_with(grey_url, headers=grey_headers)

    @patch('requests.get')
    def test_vt_hashrep(self, mock_get):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        Virustotal = api_keys["Virus Total"]
        url = f'https://www.virustotal.com/api/v3/files/sdkjn5234n23l'
        headers = {
            'accept': 'application/json',
            'x-apikey': f'{Virustotal}'
            }
        mock_response = Mock()
        response_json = {"data": {"attributes": {"total_votes": "test"}}}
        mock_response.json.return_value = response_json
        mock_get.return_value = mock_response
        vt_hash = vt_hashrep('sdkjn5234n23l')
        mock_get.assert_called_with(url, headers=headers)

    @patch('requests.get')
    def test_ha_hashrep(self, mock_get):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        HybridAnalysis = api_keys["Hybrid Analysis"]
        haurl = f'https://www.hybrid-analysis.com/api/v2/overview/sdkjn5234n23l'
        haheaders = {
            'accept': 'application/json',
            'api-key': f'{HybridAnalysis}'
            }
        mock_response = Mock()
        response_json = {"threat_score": "test", "verdict": "test"}
        mock_response.json.return_value = response_json
        mock_get.return_value = mock_response
        ha_hash = ha_hashrep('sdkjn5234n23l')
        mock_get.assert_called_with(url=haurl, headers=haheaders)

    @patch('requests.get')
    def test_cir_hashrep(self, mock_get):
        headers = {
            'accept': 'application/json',
            }
        md5_url = f'https://hashlookup.circl.lu/lookup/md5/sdkjn5234n23l'
        sha1_url = f'https://hashlookup.circl.lu/lookup/sha1/sdkjn5234n23l'
        sha256_url = f'https://hashlookup.circl.lu/lookup/sha256/sdkjn5234n23l'
        mock_response = Mock()
        response_json = {"hashlookup:trust": 0}
        mock_response.json.return_value = mock_response
        cir_hash_md5 = cir_hashrep('sdkjn5234n23l', res='md5')
        mock_get.assert_called_with(md5_url, headers=headers)
        cir_hash_sha1 = cir_hashrep('sdkjn5234n23l', res='sha1')
        mock_get.assert_called_with(sha1_url, headers=headers)
        cir_hash_sha1 = cir_hashrep('sdkjn5234n23l', res='sha256')
        mock_get.assert_called_with(sha256_url, headers=headers)

    @patch('requests.post')
    def test_urlscan_post(self, mock_post):
        with open('Config.json') as user_file:
            api_contents = user_file.read()
        api_keys = json.loads(api_contents)
        UrlScan = api_keys["UrlScan"]
        scan_url = 'https://urlscan.io/api/v1/scan/'
        headers = {
            'API-Key': f'{UrlScan}',
            'Content-Type':'application/json'
            }
        data = {
            'url': 'test.com',
            'visibility': 'public'
            }
        mock_response = Mock()
        response_json = {"uuid": "test"}
        mock_response.json.return_value = response_json
        mock_post.return_value = mock_response
        url_scan('test.com')
        mock_post.assert_called_once_with(scan_url, headers=headers, data=json.dumps(data))

    @patch('requests.get')
    def test_rescan_loop_fail_410(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 410
        mock_get.return_value = mock_response
        res = re_scan('testing')
        self.assertIsNone(res)

    @patch('requests.get')
    def test_rescan_loop_pass(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        response_json = {"verdicts": "test verdict"}
        mock_response.json.return_value = response_json
        mock_get.return_value = mock_response
        self.assertEqual(re_scan('testing'), response_json)

if __name__ == '__main__':
    unittest.main()