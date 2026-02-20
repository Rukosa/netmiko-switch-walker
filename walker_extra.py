import csv
import re
import threading
import os
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

#Set your credentials and seed switch here
seed_switch_ip = "10.100.250.1"
username = "admin"
password = "password"

#RISK THRESHOLDS
HIGH_PCT = 85
WARN_PCT = 70
MIN_REMAINING_WATTS = 50
AP_WARN_THRESHOLD = 20

#Regex for limiting which IPs will be connected to
ip_pattern = re.compile(r"^10\.(100|120|130|140|170|180)\.250\.\d{1,3}$|^10\.25\.10\.1$")

visited = set()
results = []
lock = threading.Lock()
os.makedirs("configs", exist_ok=True)

def connect_and_discover(ip, username, password, device_type="cisco_ios"):
    with lock:
        if ip in visited:
            return []
        visited.add(ip)

    neighbors = []

    try:
        connection = ConnectHandler(
            ip=ip,
            username=username,
            password=password,
            device_type=device_type,
        )
        print(f"Connected to {ip}")

        #Get hostname
        hostname = connection.send_command("show run | include hostname").strip().split()[-1]

        #Get model
        version_output = connection.send_command("show version")
        switch_model = "Unknown"

        patterns = [
            r"Model number\s*[: ]+\s*(\S+)",
            r"Model Number\s*[: ]+\s*(\S+)",
            r"System Model ID\s*[: ]+\s*(\S+)",
            r"^\s*(C\d{4,}[A-Z0-9\-]*)",
        ]

        for pat in patterns:
            match = re.search(pat, version_output, re.MULTILINE)
            if match:
                switch_model = match.group(1)
                break

        #Save config
        txt_path = os.path.join("configs", f"{hostname}.txt")
        try:
            conf_output = connection.send_command('show run')
            with open(txt_path, "w") as file:
                file.write(conf_output)
        except Exception as e:
            print(e)

        #PoE Power Budget Parsing
        power_output = connection.send_command("show power inline")

        available_watts = 0.0
        used_watts = 0.0
        remaining_watts = 0.0

        power_matches = re.findall(
            r"^\s*\d+\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)",
            power_output,
            re.MULTILINE
        )

        for match in power_matches:
            available_watts += float(match[0])
            used_watts += float(match[1])
            remaining_watts += float(match[2])

        if available_watts > 0:
            poe_utilization = round((used_watts / available_watts) * 100, 1)
        else:
            poe_utilization = 0.0

        #AP Detection via CDP
        cdp_output = connection.send_command("show cdp neighbors detail")

        ap_count = 0
        ap_model_counts = {}

        cdp_blocks = cdp_output.split("-------------------------")

        for block in cdp_blocks:
            if "Trans-Bridge" in block:
                model_match = re.search(r"Platform:\s+(.+?),", block)
                if model_match:
                    full_platform = model_match.group(1).strip()
                    parts = full_platform.split()
                    ap_model = parts[-1]

                    ap_count += 1
                    ap_model_counts[ap_model] = ap_model_counts.get(ap_model, 0) + 1

        ap_summary = ", ".join([f"{k} x{v}" for k, v in ap_model_counts.items()])

        #RISK EVALUATION LOGIC
        if available_watts == 0:
            risk_level = "NO_POE"
        else:
            risk_level = "OK"

            #Primary evaluation based on utilization
            if poe_utilization >= HIGH_PCT:
                risk_level = "HIGH"
            elif poe_utilization >= WARN_PCT:
                risk_level = "WARNING"

            #Only check remaining watts if utilization is already elevated
            if risk_level in ["HIGH", "WARNING"]:
                if remaining_watts < MIN_REMAINING_WATTS:
                    risk_level = "HIGH"

            #AP density check (non-critical)
            if ap_count >= AP_WARN_THRESHOLD and risk_level == "OK":
                risk_level = "WARNING"

        #Discover neighbors
        neighbors = re.findall(r"IP address: (\d+\.\d+\.\d+\.\d+)", cdp_output)

        #Store results
        with lock:
            results.append({
                "ip": ip,
                "hostname": hostname,
                "model": switch_model,
                "ap_count": ap_count,
                "ap_models": ap_summary,
                "poe_available_watts": round(available_watts, 1),
                "poe_used_watts": round(used_watts, 1),
                "poe_remaining_watts": round(remaining_watts, 1),
                "poe_utilization_percent": poe_utilization,
                "risk_level": risk_level
            })

        connection.disconnect()

    except Exception as e:
        print(f"Failed to connect to {ip}: {e}")

    return neighbors


def export_to_csv(filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=[
            "ip",
            "hostname",
            "model",
            "ap_count",
            "ap_models",
            "poe_available_watts",
            "poe_used_watts",
            "poe_remaining_watts",
            "poe_utilization_percent",
            "risk_level"
        ])
        writer.writeheader()
        for entry in results:
            writer.writerow(entry)


#ThreadPoolExecutor logic
with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_ip = {}
    submitted = set()

    future = executor.submit(connect_and_discover, seed_switch_ip, username, password)
    future_to_ip[future] = seed_switch_ip
    submitted.add(seed_switch_ip)

    while future_to_ip:
        for future in list(future_to_ip):
            ip = future_to_ip.pop(future)
            try:
                neighbors = future.result()
                for neighbor_ip in neighbors:
                    if not bool(ip_pattern.match(neighbor_ip)):
                        print(f"Skipping non-switch device at {neighbor_ip}")
                        continue
                    with lock:
                        if neighbor_ip not in visited and neighbor_ip not in submitted:
                            new_future = executor.submit(connect_and_discover, neighbor_ip, username, password)
                            future_to_ip[new_future] = neighbor_ip
                            submitted.add(neighbor_ip)
            except Exception as e:
                print(f"Error processing {ip}: {e}")

#Export results
export_to_csv("network_map.csv")
print("Exported to network_map.csv")