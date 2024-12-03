import csv
from collections import defaultdict, Counter
from datetime import datetime

def parse_windows_log(file_path):
    """Parse Windows log file and analyze key information."""
    log_types = defaultdict(int)
    module_actions = defaultdict(int)
    keyword_logs = defaultdict(int)
    time_based_activity = Counter()
    
    keywords = ["Error", "Failure", "Critical"]
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 4:
                continue  # Skip malformed lines
            
            # Extract log type and module
            log_type = parts[2]
            module = parts[3]
            
            # Increment counters
            log_types[log_type] += 1
            module_actions[module] += 1
            
            # Check for specific keywords in the message
            message = " ".join(parts[4:])
            for keyword in keywords:
                if keyword in message:
                    keyword_logs[keyword] += 1
            
            # Extract timestamp and categorize by hour
            try:
                timestamp = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S,")
                hour = timestamp.strftime("%Y-%m-%d %H:00:00")
                time_based_activity[hour] += 1
            except ValueError:
                continue  # Skip if timestamp format is invalid
    
    return log_types, module_actions, keyword_logs, time_based_activity

def save_to_csv(file_name, log_types, module_actions, keyword_logs, time_based_activity):
    """Save the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Log Types
        writer.writerow(["Log Type", "Count"])
        for log_type, count in log_types.items():
            writer.writerow([log_type, count])
        
        # Write Module Actions
        writer.writerow([])
        writer.writerow(["Module", "Count"])
        for module, count in module_actions.items():
            writer.writerow([module, count])
        
        # Write Keyword Logs
        writer.writerow([])
        writer.writerow(["Keyword", "Count"])
        for keyword, count in keyword_logs.items():
            writer.writerow([keyword, count])
        
        # Write Time-Based Activity
        writer.writerow([])
        writer.writerow(["Hour", "Activity Count"])
        for hour, count in sorted(time_based_activity.items()):
            writer.writerow([hour, count])

def main():
    log_file = "Windows_2k.log"  # Path to the Windows log file
    output_file = "Windows_log_analysis_enhanced_results.csv"  # Output CSV file name
    
    # Parse the Windows log file
    log_types, module_actions, keyword_logs, time_based_activity = parse_windows_log(log_file)
    
    # Display log type counts
    print("Log Type           Count")
    for log_type, count in log_types.items():
        print(f"{log_type:15} {count}")
    
    # Display module action counts
    print("\nModule             Count")
    for module, count in module_actions.items():
        print(f"{module:15} {count}")
    
    # Display keyword logs
    print("\nKeyword            Count")
    for keyword, count in keyword_logs.items():
        print(f"{keyword:15} {count}")
    
    # Display time-based activity
    print("\nHour               Activity Count")
    for hour, count in sorted(time_based_activity.items()):
        print(f"{hour:20} {count}")
    
    # Save results to CSV
    save_to_csv(output_file, log_types, module_actions, keyword_logs, time_based_activity)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
