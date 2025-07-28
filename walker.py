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
        model = "Unknown"

        #Try all common Cisco model patterns
        patterns = [
            r"Model number\s*[: ]+\s*(\S+)",       # Traditional Cisco (2960, 3560)
            r"Model Number\s*[: ]+\s*(\S+)",       # IOS-XE capitalized
            r"System Model ID\s*[: ]+\s*(\S+)",    # Some ISR/ASR/NGFW
            r"^\s*(C\d{4,}[A-Z0-9\-]*)",           # Raw model anywhere (like "C9300-48U")
        ]

        for pat in patterns:
            match = re.search(pat, version_output, re.MULTILINE)
            if match:
                model = match.group(1)
                break

        with lock:
            results.append({"ip": ip, "hostname": hostname, "model": model})

        #Config file write
        txt_path = os.path.join("configs", f"{hostname}.txt")
        try:
            conf_output = connection.send_command('show run')
            with open(txt_path, "w") as file:
                file.write(conf_output)
        except Exception as e:
            print(e)
        
        #Get neighbors via CDP
        cdp_output = connection.send_command("show cdp neighbors detail")
        neighbors = re.findall(r"IP address: (\d+\.\d+\.\d+\.\d+)", cdp_output)

        connection.disconnect()

    except Exception as e:
        print(f"Failed to connect to {ip}: {e}")
    
    return neighbors

def export_to_csv(filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["ip", "hostname", "model"])
        writer.writeheader()
        for entry in results:
            writer.writerow(entry)

#ThreadPoolExecutor logic
with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_ip = {}
    submitted = set()

    #Submit the first job
    future = executor.submit(connect_and_discover, seed_switch_ip, username, password)
    future_to_ip[future] = seed_switch_ip
    submitted.add(seed_switch_ip)

    while future_to_ip:
        done, _ = as_completed(future_to_ip), None
        for future in list(future_to_ip):
            ip = future_to_ip.pop(future)
            try:
                neighbors = future.result()
                for neighbor_ip in neighbors:
                    if neighbor_ip.startswith("10.200."): #Here is where you specify skips
                        print(f"Skipping access point at {neighbor_ip}")
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
