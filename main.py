import requests
import csv
import json
from datetime import datetime

security_headers = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "X-Permitted-Cross-Domain-Policies"
]

def get_url():
    url = input("Enter a website you want to check: ")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url

def analyze_headers(url, headers):
    found = 0
    missing = 0
    results = []

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("resultsc.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(["Scan Time", "Website", "Header", "Status", "Value"])

        print("\nSecurity Header Analysis")
        print("-"*40)

        for header_name in security_headers:
            header_value = headers.get(header_name)
            if header_value is None:
                status = "MISSING"
                value = ""
                print(f"[MISSING] {header_name}")
                missing += 1
            else:
                status = "FOUND"
                value = header_value
                print(f"[FOUND] {header_name}: {header_value}")
                found += 1

            writer. writerow([scan_time, url, header_name, status, value])
            results.append({
                "header": header_name,
                "status": status,
                "value": value
            })

    with open("resultsj.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "scan_time": scan_time,
                "website": url,
                "results": results
            },
            file,
            indent=4
        )

    return found, missing

def print_summary(found, missing):
    print("\nSummary")
    print("-"*40)
    print(f"Headers checked: {len(security_headers)}")
    print(f"Found: {found}")
    print(f"Missing: {missing}")
    print("-"*40)
    print("\nResults are saved to results.csv")
    print("Results are saved to results.json")



def main():
    url = get_url()

    try:
        response = requests.get(url, timeout=10)

        print(f"\nAnalyzing {url}...\n")

        found, missing = analyze_headers(url, response.headers)

        print_summary(found, missing)

    except requests.exceptions.ConnectionError:
        print("Could not connect to the website.")

    except requests.exceptions.Timeout:
        print("The request timed out.")

    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()