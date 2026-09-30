from pathlib import Path
from collections import Counter

log_file = Path("sample_logs/auth.log")
failed_login_ips = []

with log_file.open("r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip_address = line.split("ip=")[1].strip()
            failed_login_ips.append(ip_address)

failed_attempts = Counter(failed_login_ips)

print("=== Security Log Analysis ===")
print(f"Total failed login attempts: {len(failed_login_ips)}")
print()

for ip_address, count in failed_attempts.items():
    print(f"{ip_address}: {count} failed attempt(s)")

    if count >= 3:
        print(f"  [ALERT] Suspicious repeated login failures detected from {ip_address}")