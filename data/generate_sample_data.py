"""
generate_sample_data.py
------------------------
Generates a synthetic (fake) network traffic CSV dataset for the
ML-Based Network Anomaly Detector project.

This data is 100% synthetic / randomly generated for educational use.
It does NOT contain any real network captures, real IP addresses of
real systems, or any attack payloads. It only contains numeric/label
fields that resemble typical NetFlow-style traffic logs.

Run:
    python generate_sample_data.py
"""

import random
import csv
from datetime import datetime, timedelta

random.seed(42)

PROTOCOLS = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3389, 8080, 445, 3306]

def random_private_ip():
    """Generate a random private-range IP (RFC1918) - safe, non-routable."""
    first_octet = random.choice([10, 172, 192])
    if first_octet == 10:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    elif first_octet == 172:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_normal_row(base_time):
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": random_private_ip(),
        "dst_ip": random_private_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(COMMON_PORTS),
        "protocol": random.choice(PROTOCOLS),
        "duration": round(random.uniform(0.1, 5.0), 2),
        "packet_count": random.randint(5, 200),
        "bytes_transferred": random.randint(500, 50000),
        "failed_connections": random.choice([0, 0, 0, 1]),
    }


def generate_anomalous_row(base_time):
    """Simulate suspicious PATTERNS (e.g. port scan / brute force style volume),
    without any real exploit code or payloads - purely numeric/statistical."""
    anomaly_type = random.choice(["portscan", "bruteforce", "dos", "exfiltration"])

    row = {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": random_private_ip(),
        "dst_ip": random_private_ip(),
        "protocol": random.choice(PROTOCOLS),
    }

    if anomaly_type == "portscan":
        row["src_port"] = random.randint(1024, 65535)
        row["dst_port"] = random.randint(1, 65535)
        row["duration"] = round(random.uniform(0.01, 0.2), 2)
        row["packet_count"] = random.randint(1, 5)
        row["bytes_transferred"] = random.randint(40, 300)
        row["failed_connections"] = random.randint(3, 10)
    elif anomaly_type == "bruteforce":
        row["src_port"] = random.randint(1024, 65535)
        row["dst_port"] = random.choice([22, 3389, 21])
        row["duration"] = round(random.uniform(0.1, 1.0), 2)
        row["packet_count"] = random.randint(10, 40)
        row["bytes_transferred"] = random.randint(500, 3000)
        row["failed_connections"] = random.randint(5, 20)
    elif anomaly_type == "dos":
        row["src_port"] = random.randint(1024, 65535)
        row["dst_port"] = random.choice(COMMON_PORTS)
        row["duration"] = round(random.uniform(0.01, 0.1), 2)
        row["packet_count"] = random.randint(500, 5000)
        row["bytes_transferred"] = random.randint(100000, 2000000)
        row["failed_connections"] = random.randint(0, 3)
    else:  # exfiltration
        row["src_port"] = random.randint(1024, 65535)
        row["dst_port"] = random.choice([443, 8080])
        row["duration"] = round(random.uniform(10, 60), 2)
        row["packet_count"] = random.randint(200, 1000)
        row["bytes_transferred"] = random.randint(500000, 5000000)
        row["failed_connections"] = random.choice([0, 1])

    return row


def main(num_normal=850, num_anomalous=150, out_path="sample_network_traffic.csv"):
    rows = []
    base_time = datetime.now() - timedelta(hours=6)

    for i in range(num_normal):
        base_time += timedelta(seconds=random.randint(1, 15))
        rows.append(generate_normal_row(base_time))

    for i in range(num_anomalous):
        base_time += timedelta(seconds=random.randint(1, 15))
        rows.append(generate_anomalous_row(base_time))

    random.shuffle(rows)

    fieldnames = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "duration", "packet_count", "bytes_transferred",
        "failed_connections",
    ]

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} rows -> {out_path}")


if __name__ == "__main__":
    main()
