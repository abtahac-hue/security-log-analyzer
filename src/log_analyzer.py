from pathlib import Path
from collections import Counter, defaultdict

log_file = Path("sample_logs/auth.log")

failed_login_ips = []
successful_logins = 0
total_events = 0

failed_attempts_by_ip = defaultdict(int)
suspicious_successes = []

with log_file.open("r") as file:
    for line in file:
        total_events += 1

        ip_address = line.split("ip=")[1].strip()

        if "LOGIN_FAILED" in line:
            failed_login_ips.append(ip_address)
            failed_attempts_by_ip[ip_address] += 1

        elif "LOGIN_SUCCESS" in line:
            successful_logins += 1

            previous_failures = failed_attempts_by_ip[ip_address]

            if previous_failures >= 3:
                suspicious_successes.append(
                    (ip_address, previous_failures)
                )

failed_attempts = Counter(failed_login_ips)

print("=== Security Log Analysis ===")
print(f"Total authentication events: {total_events}")
print(f"Successful logins: {successful_logins}")
print(f"Failed login attempts: {len(failed_login_ips)}")

print("\n=== Failed Login Activity by IP ===")

for ip_address, count in failed_attempts.items():
    print(f"{ip_address}: {count} failed attempt(s)")

    if count >= 3:
        print(
            f"  [ALERT] Suspicious repeated login failures detected "
            f"from {ip_address}"
        )

print("\n=== Successful Login After Repeated Failures ===")

if suspicious_successes:
    for ip_address, failed_count in suspicious_successes:
        print(
            f"[ALERT] {ip_address} successfully authenticated after "
            f"{failed_count} previous failed attempt(s)"
        )
else:
    print("No suspicious successful logins detected.")
    