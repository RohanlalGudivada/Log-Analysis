import re
import csv
from collections import defaultdict, Counter

# Threshold that can be configured to detect suspicious activity
FAILED_LOGIN_THRESHOLD = 1

def parse_log_file(file_path):
    """
    Parses the log file and extracts useful information.
    """
    ip_request_count = Counter()
    endpoint_access_count = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as log_file:

        for line in log_file:   #Extracting IP address, endpoint and failed login attempts from log file using this loop
            # Extracting IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue
            ip_address = ip_match.group(1)

            # Extracting the endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s(/[^ ]*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_count[endpoint] += 1

            # Counting IP requests
            ip_request_count[ip_address] += 1

            # Checking for failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                failed_logins[ip_address] += 1

    return ip_request_count, endpoint_access_count, failed_logins

def generate_report(ip_request_count, endpoint_access_count, failed_logins):
    """
    Generates the required report and saves to CSV.
    """
    #Counting Requests per IP address
    print("Requests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    sorted_ips = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<15}")

    #Finding Most Accessed Endpoint
    most_accessed_endpoint, max_access_count = max(endpoint_access_count.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

    #Detecting Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    for ip, count in flagged_ips.items():
        print(f"{ip:<20} {count:<15}")

    #Writing the output to CSV file named log_analysis_results.csv
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        #Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ips)
        writer.writerow([])

        #Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint, max_access_count])
        writer.writerow([])

        #Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(flagged_ips.items())

def main():
    log_file_path = 'sample.log'
    ip_request_count, endpoint_access_count, failed_logins = parse_log_file(log_file_path)
    generate_report(ip_request_count, endpoint_access_count, failed_logins)

if __name__ == "__main__":
    main()
