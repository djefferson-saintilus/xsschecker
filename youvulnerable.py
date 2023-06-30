import requests
import argparse
import sys
import urllib.parse
import os.path
import threading

# Define colors for output
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def check_vulnerability(url, payload, method, vulnerability_param):
    if method == 'get':
        # URL-encode the payload before appending it to the URL string
        encoded_payload = urllib.parse.quote(payload)
        req = requests.get(url + f"?{vulnerability_param}={encoded_payload}")
    elif method == 'post':
        req = requests.post(url, data={vulnerability_param: payload})

    if payload in req.text:
        print(f"{GREEN}[+] The payload '{payload}' triggered a response from the server. Vulnerable!{RESET}")
        return True
    else:
        print(f"{RED}[-] The payload '{payload}' did not trigger a response from the server.{RESET}")
        return False

# Define a function that checks a single payload for vulnerability and appends it to a shared list if it is vulnerable
def check_payload(payload, url, method, vulnerability_param, vulnerable_payloads):
    if method == 'get':
        is_vulnerable = check_vulnerability(url, payload, method, vulnerability_param)
    elif method == 'post':
        is_vulnerable = check_vulnerability(url, payload, method, vulnerability_param)

    if is_vulnerable:
        vulnerable_payloads.append(payload)

def main():
    parser = argparse.ArgumentParser(description='XSS vulnerability checker')
    parser.add_argument('url', help='The URL to check for XSS vulnerability')
    parser.add_argument('wordlist', help='The file containing the XSS payloads')
    parser.add_argument('--vulnerability_param', help='The parameter to check for vulnerability', default='vulnerable')
    parser.add_argument('--method', help='The HTTP method to use for the request', default='get', choices=['get', 'post'])
    args = parser.parse_args()

    url = args.url
    wordlist_file = args.wordlist
    vulnerability_param = args.vulnerability_param
    method = args.method

    try:
        # Check if the URL is valid
        requests.get(url)
    except requests.exceptions.RequestException as e:
        print(f"{RED}[-] Invalid URL: {e}{RESET}")
        sys.exit(1)

    try:
        # Check if the vulnerability parameter exists in the page source
        req = requests.get(url)
        if vulnerability_param not in req.text:
            print(f"{RED}[-] The vulnerability parameter '{vulnerability_param}' does not exist in the page source.{RESET}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"{RED}[-] Failed to retrieve page source: {e}{RESET}")
        sys.exit(1)

    # Check if the wordlist file exists and is not empty
    if not os.path.isfile(wordlist_file):
        print(f"{RED}[-] Wordlist file not found.{RESET}")
        sys.exit(1)

    with open(wordlist_file) as f:
        payloads = f.readlines()
        payloads = [x.strip() for x in payloads]

    if not payloads:
        print(f"{RED}[-] Wordlist is empty.{RESET}")
        sys.exit(1)

    
    print(f"[*] Testing {len(payloads)} payloads on {url} using {method.upper()} method...")

    # Set up the vulnerable payloads list and the worker threads
    vulnerable_payloads = []
    threads = []

    # Start a thread for each payload in the wordlist
    for payload in payloads:
        t = threading.Thread(target=check_payload, args=(payload, url, method, vulnerability_param, vulnerable_payloads))
        t.start()
        threads.append(t)

    # Wait for all threads to finish before continuing
    for t in threads:
        t.join()

    # Print the vulnerable payloads
    print(f"\n[*] Done.")
    print(f"\nSummary:")
    print(f"{GREEN}[+] Found {len(vulnerable_payloads)} vulnerable payloads:{RESET}")
    for payload in vulnerable_payloads:
        print(f"\t{GREEN}{payload}{RESET}")



if __name__ == '__main__':
    main()
