"""
This example program allows a user to pass a URL as a command line argument during script execution.

EXAMPLE: python3 url_scan_report.py testphp.vulnweb.com

This will return the list of security vendors who have marked the URL as clean or malicious, 
and can be used to score the trust worthiness of a URL.

NOTICE: In order to use this program you will need an API key that has
privileges for using the VirusTotal Feed API.

Developed by @David-M-Berry
"""

import argparse
import os
import time
import vt

def scan_url(client, url):
    """Initiates a scan for the given URL and returns the scan ID."""
    print(f"Scanning URL: {url}")
    try:
        analysis = client.scan_url(url)
        print(f"URL scan started: {analysis.id}")
        return analysis.id
    except vt.error.APIError as e:
        print(f"APIError: {e}")
    except Exception as e:
        print(f"An error occurred during URL scan: {e}")
    return None

def get_url_report(client, scan_id):
    """Fetches the report for the given scan ID."""
    print(f"Fetching report for scan ID: {scan_id}")
    try:
        # Fetch the analysis using the scan ID
        analysis = client.get_object(f"/analyses/{scan_id}")
        return analysis
    except vt.error.APIError as e:
        print(f"APIError: {e}")
    except Exception as e:
        print(f"An error occurred while fetching the report: {e}")
    return None

def wait_for_scan_completion(client, scan_id, timeout=300):
    """Waits for the scan to complete by checking the status periodically."""
    print("Waiting for the scan to complete...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        report = get_url_report(client, scan_id)
        if report.status == "completed":
            return report
        time.sleep(10)
    print("Scan did not complete in the expected time.")
    return None

def format_report(report):
    """Formats and prints the URL scan report."""
    if not report:
        print("No report available.")
        return
    
    print(f"\nURL Scan Report:")
    print(f"Scan ID: {report.id}")
    print("Last analysis stats:")
    for key, value in report.stats.items():
        print(f"  {key}: {value}")
    print("\nDetailed analysis:")
    for engine, result in report.results.items():
        print(f"  {engine}: {result['category']}")

def main():
    parser = argparse.ArgumentParser(description="Scan a URL with VirusTotal and get the report.")
    parser.add_argument("url", help="URL to scan")
    args = parser.parse_args()

    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        print("Error: Please set the VT_API_KEY environment variable.")
        return

    client = vt.Client(api_key)

    try:
        scan_id = scan_url(client, args.url)
        if not scan_id:
            print("URL scan failed.")
            return

        report = wait_for_scan_completion(client, scan_id)
        format_report(report)

    except vt.error.APIError as e:
        print(f"APIError: {e}")
        if e.args[0] == 'ForbiddenError':
            print("You are not authorized to perform the requested operation. Please check your API key permissions.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main()
