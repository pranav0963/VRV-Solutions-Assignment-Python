import re
import csv
from collections import Counter

# Threshold for suspicious activity
failed_login_threshold = 10

# Data structures to store analysis results
ip_request_counts = Counter()
endpoint_counts = Counter()
failed_login_attempts = Counter()

# Regex patterns
ip_pattern = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})')      #A simple alternative of this line is -- ip_pattern = re.compile(r'^([\d\.]+)')
endpoint_pattern = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (/[^ ]*) HTTP')     #A simple alternative of this line is -- endpoint_pattern = re.compile(r'"[A-Z]+ (/\S*) HTTP')
failed_login_pattern = re.compile(r' 401 .*Invalid credentials')

# Parse the log file
with open('./sample.log', 'r') as file:
    for line in file:
        # Extract IP addresses
        ip_match = ip_pattern.match(line)
        print(ip_match)
        if ip_match:
            ip_request_counts[ip_match.group(1)] += 1

        # Extract endpoints
        endpoint_match = endpoint_pattern.search(line)
        if endpoint_match:
            endpoint_counts[endpoint_match.group(1)] += 1

        # Detect failed logins
        if failed_login_pattern.search(line):
            failed_login_attempts[ip_match.group(1)] += 1

# Results
sorted_ip_requests = ip_request_counts.most_common()
most_accessed_endpoint, max_access_count = endpoint_counts.most_common(1)[0]
suspicious_activities = [(ip, count) for ip, count in failed_login_attempts.items() if count > failed_login_threshold]

# Display results in terminal
print("IP Address Requests:")
for ip, count in sorted_ip_requests:
    print(f"{ip:20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_activities:
    for ip, count in suspicious_activities:
        print(f"{ip:20} {count}")
else:
    print("No suspicious activity detected.")

# Save results to CSV
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    
    # IP Requests
    csv_writer.writerow(["IP Address", "Request Count"])
    csv_writer.writerows(sorted_ip_requests)
    
    # Most Accessed Endpoint
    csv_writer.writerow([])
    csv_writer.writerow(["Most Accessed Endpoint", "Access Count"])
    csv_writer.writerow([most_accessed_endpoint, max_access_count])
    
    # Suspicious Activity
    csv_writer.writerow([])
    csv_writer.writerow(["IP Address", "Failed Login Count"])
    csv_writer.writerows(suspicious_activities)


# I have also tried using parse function which works partially. Still has to work on how to parse the "invalid credentials", as it is not present in all the lines
# from parse import parse
# import pandas as pd

# with open('./sample.log','r') as file:
#     data = file.readlines()

# format = '{host} - - [{time}] "{method} {path} {protocol}" {status:d} {size:d} {message}'
# parsed_data = map(lambda x: parse(format, x).named, data)
# df = pd.DataFrame(parsed_data)
# print(df)
# print(df['host'].value_counts())
# print(df['path'].value_counts().idxmax())
# print(df[df['status'] == 401]['host'].value_counts())