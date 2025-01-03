# Log-Analysis-Script

# Log Analysis Script: Multi-OS Support

## Overview

This project contains a set of Python scripts designed to analyze system log files from multiple operating systems, including **Linux**, **Windows**, **Mac**, and **Android**. The scripts process log files to extract and categorize key information, providing insights into system activities, errors, and performance.

---

## Features

### Common Features Across All OS:
- **Log Type Categorization**: Counts occurrences of each log type (e.g., Info, Debug, Error).
- **Keyword Detection**: Identifies logs containing specific keywords (e.g., Error, Failure, Critical, Crash).
- **Time-Based Analysis**: Groups log entries by time (hour or minute) to detect trends.
- **CSV Export**: Saves the analysis results into structured CSV files for further review.

### OS-Specific Features:
#### **Linux Logs**:
- Processes logs with IP addresses, system events, and status codes.
- Detects suspicious activity (e.g., failed login attempts).
- Categorizes requests by IP address and counts endpoint accesses.

#### **Windows Logs**:
- Analyzes system logs generated by modules like CBS and CSI.
- Categorizes logs by type (e.g., Info, Error).
- Tracks module-specific actions.

#### **Mac Logs**:
- Analyzes kernel, network, and process-level logs.
- Groups logs by processes (e.g., WindowManager, PowerManagerService).
- Tracks frequent transitions and specific system events.

#### **Android Logs**:
- Processes system debugging logs with priorities (e.g., Debug, Verbose).
- Groups logs by sources (e.g., WindowManager, PowerManagerService).
- Tracks occurrences of key issues like app crashes and system failures.

---

## File Structure

- **Scripts**:
  - `log_analysis_for_linux.py`: Script for Linux log analysis.
  - `log_analysis_for_windows.py`: Script for Windows log analysis.
  - `log_analysis_for_mac.py`: Script for Mac log analysis.
  - `log_analysis_for_android.py`: Script for Android log analysis.
  
- **Log Files**:
  - `Linux_2k.log`: Example Linux log file.
  - `Windows_2k.log`: Example Windows log file.
  - `Mac_2k.log`: Example Mac log file.
  - `Android_2k.log`: Example Android log file.

- **Output**:
  - Each script generates a CSV file summarizing the analysis results (e.g., `Linux_log_analysis_results.csv`).

---

## How to Run

1. **Prerequisites**:
   - Install Python 3.6 or higher.
   - Ensure `pip` is installed to manage Python packages.

2. **Run a Script**:
   - Place the respective log file (e.g., `Linux_2k.log`) in the script directory.
   - Execute the corresponding script:
     ```bash
     python log_analysis_for_linux.py
     ```

3. **Output**:
   - Check the terminal for insights.
   - Open the generated CSV file (e.g., `Linux_log_analysis_results.csv`) for a detailed breakdown.

---

## Output Format

### CSV File Structure:
- **Log Type and Count**:
  ```
  Log Type, Count
  ```
- **Source or Module and Count**:
  ```
  Source, Count
  ```
- **Keyword and Count**:
  ```
  Keyword, Count
  ```
- **Time-Based Activity**:
  ```
  Hour or Minute, Activity Count
  ```

---

## Example Outputs

### Linux Log Analysis:
- Terminal:
  ```
  IP Address           Request Count
  192.168.1.1          234
  203.0.113.5          187
  ```
- CSV:
  - **Requests per IP**
  - **Most Accessed Endpoint**
  - **Suspicious Activities**

### Windows Log Analysis:
- Terminal:
  ```
  Log Type           Count
  Info               2000
  Module             Count
  CBS                1973
  CSI                27
  ```
- CSV:
  - **Log Type and Count**
  - **Module and Count**

### Mac Log Analysis:
- Terminal:
  ```
  Process            Count
  kernel             50
  PowerManagerService 20
  Keyword            Count
  Error              5
  ```
- CSV:
  - **Process and Count**
  - **Keyword and Count**
  - **Time-Based Activity**

### Android Log Analysis:
- Terminal:
  ```
  Log Priority       Count
  D                  1000
  V                  500
  Source             Count
  WindowManager      200
  ```
- CSV:
  - **Log Priority and Count**
  - **Source and Count**
  - **Time-Based Activity**


