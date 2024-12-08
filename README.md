# README for Log Analysis Script

## Overview

This project is a Python-based **Log Analysis Tool** designed to parse web server log files, extract key information, and generate a comprehensive report. The report provides insights into:

1. The number of requests made by each IP address.
2. The most frequently accessed endpoints.
3. Detection of suspicious activity, such as multiple failed login attempts.

The tool also saves the analyzed data into a CSV file (`log_analysis_results.csv`).

---

## Features

- **Parse Log Files:** Extracts IP addresses, accessed endpoints, and failed login attempts from a log file.
- **Analyze Data:**
  - Counts requests per IP address.
  - Identifies the most accessed endpoint.
  - Flags IP addresses with failed login attempts exceeding a configurable threshold.
- **Generate Reports:**
  - Outputs data to the console.
  - Saves results to a CSV file (`log_analysis_results.csv`) for further analysis.

---

## Requirements

- Python 3.x
- Libraries: 
  - `re`
  - `csv`
  - `collections`

---

## Usage

### 1. Clone the Repository

```bash
git clone <https://github.com/RohanlalGudivada/Log-Analysis>
cd <repository-folder>
```

### 2. Prepare the Log File

Ensure your log file (e.g., `sample.log`) is in the same directory as the script. The log file should follow standard web server log formats.

### 3. Run the Script

Execute the script using the following command:

```bash
python log_analysis.py
```

### 4. View the Results

- **Console Output:**
  - Requests per IP address.
  - Most frequently accessed endpoint.
  - List of flagged IPs with suspicious activity.
- **CSV Output:**
  The results are saved in `log_analysis_results.csv` in the following structure:
  - Requests per IP
  - Most Accessed Endpoint
  - Suspicious Activity

---

## Configuration

- **Failed Login Threshold:**  
  To modify the threshold for detecting suspicious activity, change the value of `FAILED_LOGIN_THRESHOLD` in the script:

  ```python
  FAILED_LOGIN_THRESHOLD = 1  # Default: 1
  ```

---

## Example Input and Output

### Input: `sample.log`

Sample log lines:

```
192.168.1.1 - - [10/Dec/2024:10:00:00 +0000] "GET /home HTTP/1.1" 200 1234
192.168.1.2 - - [10/Dec/2024:10:05:00 +0000] "POST /login HTTP/1.1" 401 567
192.168.1.1 - - [10/Dec/2024:10:10:00 +0000] "GET /dashboard HTTP/1.1" 200 987
```

### Console Output

```
Requests per IP Address:
IP Address           Request Count
192.168.1.1          2
192.168.1.2          1

Most Frequently Accessed Endpoint:
/home (Accessed 1 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.2          1
```

### CSV Output: `log_analysis_results.csv`

```
Requests per IP
IP Address,Request Count
192.168.1.1,2
192.168.1.2,1

Most Accessed Endpoint
Endpoint,Access Count
/home,1

Suspicious Activity
IP Address,Failed Login Count
192.168.1.2,1
```

---
## License

This project is licensed under the MIT License. Feel free to use and modify it as needed.

--- 
