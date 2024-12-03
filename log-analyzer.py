import re
import csv
from concurrent.futures import ProcessPoolExecutor

# File paths
log_file = "/content/sample_log.txt"
output_csv = "log_analysis_results.csv"

# Constants
FAILED_LOGIN_CODE = "401"
FAILED_LOGIN_MESSAGE = "Invalid credentials"
FAILED_LOGIN_THRESHOLD = 5
CHUNK_SIZE = 5  # Number of lines per chunk


def process_log_file_in_chunks(file_path, chunk_size=CHUNK_SIZE):
    """Yields chunks of lines from the log file."""
    with open(file_path, "r") as file:
        chunk = []
        for line in file:
            chunk.append(line)
            if len(chunk) == chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk  # Yield the final chunk


def count_requests_per_ip(chunk):
    """Counts the number of requests made by each IP in a chunk."""
    ip_request_count = {}
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for line in chunk:
        ip_match = ip_pattern.search(line)
        if ip_match:
            ip = ip_match.group(1)
            ip_request_count[ip] = ip_request_count.get(ip, 0) + 1

    return ip_request_count


def find_most_accessed_endpoint(chunk):
    """Finds the most frequently accessed endpoints in a chunk."""
    endpoint_access_count = {}
    endpoint_pattern = re.compile(r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.+?) HTTP')

    for line in chunk:
        endpoint_match = endpoint_pattern.search(line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_access_count[endpoint] = endpoint_access_count.get(endpoint, 0) + 1

    return endpoint_access_count


def detect_suspicious_activity(chunk):
    """Detects suspicious activity (failed login attempts) in a chunk."""
    failed_login_count = {}
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for line in chunk:
        if FAILED_LOGIN_CODE in line and FAILED_LOGIN_MESSAGE in line:
            ip_match = ip_pattern.search(line)
            if ip_match:
                ip = ip_match.group(1)
                failed_login_count[ip] = failed_login_count.get(ip, 0) + 1

    return failed_login_count


def merge_results(results_list):
    """Merges dictionaries of results from different chunks."""
    merged = {}
    for result in results_list:
        for key, value in result.items():
            merged[key] = merged.get(key, 0) + value
    return merged


def analyze_chunk(chunk):
    """Processes a single chunk and returns partial results."""
    ip_counts = count_requests_per_ip(chunk)
    endpoint_counts = find_most_accessed_endpoint(chunk)
    suspicious_activities = detect_suspicious_activity(chunk)
    return ip_counts, endpoint_counts, suspicious_activities


def perform_log_rotation(log_file_path, processed_log_path):
    """Rotates logs by moving processed logs to a different file."""
    with open(log_file_path, "r") as log_file:
        lines = log_file.readlines()

    with open(processed_log_path, "w") as processed_file:
        processed_file.writelines(lines)

    # Clear the original log file
    with open(log_file_path, "w") as log_file:
        log_file.truncate(0)


def write_to_csv(file_path, ip_counts, most_accessed, suspicious_ips):
    """Writes results to a CSV file."""
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts.items())

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())


def main():
    """Main function to execute the log analysis."""
    chunks = process_log_file_in_chunks(log_file)

    # Parallel processing with a process pool
    with ProcessPoolExecutor() as executor:
        results = executor.map(analyze_chunk, chunks)

    # Combine results
    ip_results = []
    endpoint_results = []
    suspicious_results = []

    for ip_counts, endpoint_counts, suspicious_activities in results:
        ip_results.append(ip_counts)
        endpoint_results.append(endpoint_counts)
        suspicious_results.append(suspicious_activities)

    merged_ip_counts = merge_results(ip_results)
    merged_endpoint_counts = merge_results(endpoint_results)
    merged_suspicious_activities = merge_results(suspicious_results)

    # Determine the most accessed endpoint
    most_accessed = max(merged_endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))

    # Filter suspicious IPs by threshold
    suspicious_ips = {ip: count for ip, count in merged_suspicious_activities.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("Requests per IP Address:")
    for ip, count in sorted(merged_ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed[0]}: {most_accessed[1]} accesses")

    print("\nSuspicious Activity (IPs with failed logins exceeding the threshold):")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")

    # Write results to CSV
    write_to_csv(output_csv, merged_ip_counts, most_accessed, suspicious_ips)


if __name__ == "__main__":
    main()
