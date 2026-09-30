# Security Log Analyzer

A Python-based security log analysis tool that identifies suspicious authentication activity from system login logs.

I built this project as part of my cybersecurity learning to practice working with authentication logs and translating common security monitoring concepts into Python. The goal was to create a simple defensive security tool that can separate normal authentication activity from patterns that may deserve further investigation.

## What It Detects

The analyzer currently identifies:

- Failed authentication attempts
- Repeated failed logins from the same IP address
- Successful authentication after multiple previous failures from the same IP
- Authentication statistics including total events, successful logins, and failed logins

The current alert threshold is three failed login attempts.

## Example Detection

The included sample log simulates several authentication events. One IP address generates five failed login attempts followed by a successful authentication.

The analyzer flags both the repeated failures and the later successful login for further investigation.

Example output:

```text
=== Security Log Analysis ===
Total authentication events: 11
Successful logins: 5
Failed login attempts: 6

=== Failed Login Activity by IP ===
203.0.113.42: 5 failed attempt(s)
  [ALERT] Suspicious repeated login failures detected from 203.0.113.42
198.51.100.17: 1 failed attempt(s)

=== Successful Login After Repeated Failures ===
[ALERT] 203.0.113.42 successfully authenticated after 5 previous failed attempt(s)
```

## Project Structure

```text
security-log-analyzer/
├── sample_logs/
│   └── auth.log
├── src/
│   └── log_analyzer.py
└── README.md
```

## How to Run

### Requirements

- Python 3

### Run the analyzer

From the project directory:

```bash
python src/log_analyzer.py
```

The program reads the authentication events in `sample_logs/auth.log` and prints the analysis to the terminal.

## How It Works

The analyzer processes authentication events in chronological order. It tracks failed login attempts by IP address and generates an alert when an IP reaches the configured failure threshold.

If that same IP later successfully authenticates after reaching the threshold, the program generates an additional alert. This can help surface authentication behavior that may warrant further investigation.

## Security Context

Repeated authentication failures can occur for many reasons, including forgotten credentials, misconfigured applications, or automated credential guessing. A successful login following repeated failures can also be significant during an investigation.

These patterns are treated as indicators for further analysis rather than proof of malicious activity.

## Technologies

- Python
- Git
- GitHub
- Authentication log analysis
- Defensive security concepts

## Future Improvements

Potential improvements include:

- Support for command-line log file input
- Time-window-based detection
- Username-based analysis
- Exporting alerts to CSV or JSON
- Additional authentication detection rules
- Visualization of authentication trends

## Author

**Abtaha Chowdhury**

Cybersecurity student at Florida International University

[LinkedIn](https://www.linkedin.com/in/abtahac)
