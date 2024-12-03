import csv
from collections import defaultdict, Counter
from datetime import datetime

def parse_mac_log(file_path):
    """Parse Mac log file and analyze key information."""
    process_counts = defaultdict(int)
    keyword_logs = defaultdict(int)
    time_based_activity = Counter()
    
    keywords = ["Error", "Failure", "Critical", "unplug", "disconnect"]
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 5:
                continue  
            
            process = parts[3].split('[')[0] if '[' in parts[3] else parts[3]
            process_counts[process] += 1
            
            message = " ".join(parts[4:])
            for keyword in keywords:
                if keyword in message:
                    keyword_logs[keyword] += 1
            
            try:
                timestamp_str = " ".join(parts[:3]) + " 2024"  # Assuming the year is 2024
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
                hour = timestamp.strftime("%Y-%m-%d %H:00:00")
                time_based_activity[hour] += 1
            except ValueError:
                continue  
    
    return process_counts, keyword_logs, time_based_activity

def save_to_csv(file_name, process_counts, keyword_logs, time_based_activity):
    """Save the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(["Process", "Count"])
        for process, count in process_counts.items():
            writer.writerow([process, count])
        
        writer.writerow([])
        writer.writerow(["Keyword", "Count"])
        for keyword, count in keyword_logs.items():
            writer.writerow([keyword, count])
        
        writer.writerow([])
        writer.writerow(["Hour", "Activity Count"])
        for hour, count in sorted(time_based_activity.items()):
            writer.writerow([hour, count])

def main():
    log_file = "Mac_2k.log"  
    output_file = "Mac_log_analysis_results.csv"  
    
    process_counts, keyword_logs, time_based_activity = parse_mac_log(log_file)
    
    print("Process            Count")
    for process, count in process_counts.items():
        print(f"{process:15} {count}")
    
    print("\nKeyword            Count")
    for keyword, count in keyword_logs.items():
        print(f"{keyword:15} {count}")
    
    print("\nHour               Activity Count")
    for hour, count in sorted(time_based_activity.items()):
        print(f"{hour:20} {count}")
    
    save_to_csv(output_file, process_counts, keyword_logs, time_based_activity)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
