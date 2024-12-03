import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

def parse_custom_log(file_path):
    """Parse the custom log file and extract key information."""
    ip_requests = defaultdict(int)
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            if 'rhost=' in line:
                parts = line.split()
                ip = None
                for part in parts:
                    if part.startswith('rhost='):
                        ip = part.split('=')[1]
                        break
                if ip:
                    ip_requests[ip] += 1
                
                if 'authentication failure' in line:
                    failed_logins[ip] += 1
    
    return ip_requests, failed_logins

def save_to_csv(file_name, ip_requests, suspicious_activities):
    """Save the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activities.items():
            if count > FAILED_LOGIN_THRESHOLD:  # Ensure threshold is applied
                writer.writerow([ip, count])

def main():
    log_file = "Linux_2k.log"  
    output_file = "Linux_log_analysis_results.csv"      
    ip_requests, failed_logins = parse_custom_log(log_file)
    
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")
    
    suspicious_activities = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    if suspicious_activities:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(f"{ip:20} {count}")
    else:
        print("\nNo Suspicious Activity Detected.")
    
    save_to_csv(output_file, ip_requests, suspicious_activities)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
