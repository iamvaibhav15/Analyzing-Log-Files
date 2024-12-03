import re
import csv
from collections import defaultdict, Counter

# Define the path to the log file
file_path = 'V:/Coding/Project/sample2.log'

# Define the regex pattern and compile it once ( works for IPv4 as well as IPv6 )
sample_pattern = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3} |([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4} |(([a-fA-F0-9]{1,4}:){0,7}[a-fA-F0-9]{1,4})?::   # (([a-fA-F0-9]{1,4}:){0,7}[a-fA-F0-9]{1,4})?)- - '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[A-Z]+) (?P<url>\/\S*?) HTTP\/1\.1" '
    r'(?P<status_code>\d+) (?P<response_size>\d+)(?: (?P<additional_info>"[^"]*"))?'
)

# Initialize counters and data structures
count_ips = defaultdict(int)
count_urls = Counter()
failed_login_ips = defaultdict(int)

# Process the log file line by line
with open(file_path, 'r') as file:
    for line in file:
        # Match the line with the regex pattern
        match = sample_pattern.match(line)
        if match:
            # Extract details from the matched groups
            ip = match['ip']
            url = match['url']
            status_code = match['status_code']
            additional_info = match['additional_info'] or ""
            
            # Update counters
            count_ips[ip] += 1
            count_urls[url] += 1

            # Detect failed login attempts
            if status_code == '401' or 'Invalid credentials' in additional_info:
                failed_login_ips[ip] += 1

# Setting threshold for failed login attempts
failure_threshold = 10
sus_ips = {ip: count for ip, count in failed_login_ips.items() if count > failure_threshold}

# Task 1: Print IP Frequency
print(f"{'IP Address':<18}{'Request Count'}")
for ip, count in count_ips.items():
    print(f"{ip:<18}{count}")

# Task 2: Find and print the most frequently accessed endpoint
most_accessed_url, most_accessed_count = count_urls.most_common(1)[0]
print(f"\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_url} (Accessed {most_accessed_count} times)")

# Task 3: Print flagged IPs with failed login attempts
if sus_ips:
    print(f"\nSuspicious Activity Detected:")
    print(f"{'IP Address':<18}{'Failed Login Attempts'}")
    for ip, count in sus_ips.items():
        print(f"{ip:<18}{count}")
else:
    print("\nNo suspicious activity detected.")

# Save results to a CSV file
csv_file_path = 'log_analysis_results2.csv'
data = []

# Task 1: Requests per IP
data.append(["Requests per IP"])
data.append(["IP Address", "Request Count"])
data.extend([[ip, count] for ip, count in count_ips.items()])

# Task 2: Most Accessed Endpoint
data.append(["\nMost Accessed Endpoint"])
data.append(["Endpoint", "Access Count"])
data.append([most_accessed_url, most_accessed_count])

# Task 3: Suspicious Activity
data.append(["\nSuspicious Activity"])
if sus_ips:
    data.append(["IP Address", "Failed Login Count"])
    data.extend([[ip, count] for ip, count in sus_ips.items()]) 
else:
    data.append(["No suspicious activity detected."])

# Write data to CSV
with open(csv_file_path, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerows(data)

print(f"\nResults saved to {csv_file_path}")
