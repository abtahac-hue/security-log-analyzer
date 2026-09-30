from pathlib import Path
from collections import Counter, defaultdict

LOG_FILE = Path("sample_logs/auth.log")
ALERT_THRESHOLD = 3


def analyze_log(log_file):
    failed_login_ips = []
    failed_attempts_by_ip = defaultdict(int)
    suspicious_successes = []

    successful_logins = 0
    total_events = 0

    with log_file.open("r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            total_events += 1

            if "ip=" not in line:
                continue

            ip_address = line.split("ip=")[1].strip()

            if "LOGIN_FAILED" in line:
                failed_login_ips.append(ip_address)
                failed_attempts_by_ip[ip_address] += 1

            elif "LOGIN_SUCCESS" in line:
                successful_logins += 1
                previous_failures = failed_attempts_by_ip[ip_address]

                if previous_failures >= ALERT_THRESHOLD:
                    suspicious_successes.append(
                        (ip_address, previous_failures)
                    )

    return (
        total_events,
        successful_logins,
        failed_login_ips,
        suspicious_successes,
    )


def display_results(
    total_events,
    successful_logins,
    failed_login_ips,
    suspicious_successes,
):
    failed_attempts = Counter(failed_login_ips)

    print("\n=== Security Log Analysis ===")
    print(f"Total authentication events: {total_events}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed login attempts: {len(failed_login_ips)}")

    print("\n=== Failed Login Activity by IP ===")

    if not failed_attempts:
        print("No failed login attempts detected.")

    for ip_address, count in failed_attempts.items():
        print(f"{ip_address}: {count} failed attempt(s)")

        if count >= ALERT_THRESHOLD:
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


def main():
    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    results = analyze_log(LOG_FILE)
    display_results(*results)


if __name__ == "__main__":
    main()