import csv
from collections import defaultdict, Counter
from datetime import datetime

def parse_android_log(file_path):
    """Parse Android log file and analyze key information."""
    log_priorities = defaultdict(int)
    source_counts = defaultdict(int)
    keyword_logs = defaultdict(int)
    time_based_activity = Counter()
    
    keywords = ["Error", "Failure", "Crash"]
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 5:
                continue  
            
            log_priority = parts[4]
            log_priorities[log_priority] += 1
            
            source = parts[5] if len(parts) > 5 else "Unknown"
            source_counts[source] += 1
            
            message = " ".join(parts[6:])
            for keyword in keywords:
                if keyword in message:
                    keyword_logs[keyword] += 1
            
            try:
                timestamp_str = " ".join(parts[:2])  
                timestamp = datetime.strptime(timestamp_str, "%m-%d %H:%M:%S.%f")
                minute = timestamp.strftime("%Y-%m-%d %H:%M")
                time_based_activity[minute] += 1
            except ValueError:
                continue  
    
    return log_priorities, source_counts, keyword_logs, time_based_activity

def save_to_csv(file_name, log_priorities, source_counts, keyword_logs, time_based_activity):
    """Save the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(["Log Priority", "Count"])
        for priority, count in log_priorities.items():
            writer.writerow([priority, count])
        
        writer.writerow([])
        writer.writerow(["Source", "Count"])
        for source, count in source_counts.items():
            writer.writerow([source, count])
        
        writer.writerow([])
        writer.writerow(["Keyword", "Count"])
        for keyword, count in keyword_logs.items():
            writer.writerow([keyword, count])
        
        writer.writerow([])
        writer.writerow(["Minute", "Activity Count"])
        for minute, count in sorted(time_based_activity.items()):
            writer.writerow([minute, count])

def main():
    log_file = "Android_2k.log" 
    output_file = "Android_log_analysis_results.csv" 
    
    # Parse the Android log file
    log_priorities, source_counts, keyword_logs, time_based_activity = parse_android_log(log_file)
    
    print("Log Priority       Count")
    for priority, count in log_priorities.items():
        print(f"{priority:15} {count}")
    
    print("\nSource             Count")
    for source, count in source_counts.items():
        print(f"{source:15} {count}")
    
    print("\nKeyword            Count")
    for keyword, count in keyword_logs.items():
        print(f"{keyword:15} {count}")
    
    print("\nMinute             Activity Count")
    for minute, count in sorted(time_based_activity.items()):
        print(f"{minute:20} {count}")
    
    save_to_csv(output_file, log_priorities, source_counts, keyword_logs, time_based_activity)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
