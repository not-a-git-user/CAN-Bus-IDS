import can
import time
import random
import sys
import threading
import json
import os
import struct  # Required for packing floats
from datetime import datetime
from colorama import Fore, Style, init
import argparse

from crypto_utils import encrypt_data

parser = argparse.ArgumentParser()
parser.add_argument("--input_file", default="telemetry_full_standardized.json", help="Path to the telemetry JSON file")
parser.add_argument("--encrypt", action="store_true", help="Encrypt JSON logs")
parser.add_argument("--encrypt_key", default=os.getenv("CAN_ENCRYPTION_KEY"), help="Encryption key")
args = parser.parse_args()

INPUT_FILE = args.input_file
ENCRYPTION_KEY = args.encrypt_key
USE_ENCRYPTION = args.encrypt or bool(ENCRYPTION_KEY)

if USE_ENCRYPTION and not ENCRYPTION_KEY:
    print("Error: encryption enabled but no key provided")
    sys.exit(1)

LOG_DIR = "sent_logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"log_{timestamp_str}.json")
log_lock = threading.Lock()

try:
    init()
    bus = can.interface.Bus(interface='socketcan', channel='vcan0')
except OSError:
    print("Can't bind to vcan0 interface")
    sys.exit(1)

def log_to_file(entry):
    with log_lock:
        with open(LOG_FILE, "a") as f:
            if USE_ENCRYPTION:
                f.write(encrypt_data(entry, ENCRYPTION_KEY).decode("utf-8") + "\n")
            else:
                f.write(json.dumps(entry) + "\n")

def sensors(id, name, interval, limits):
    min_l = limits[0]
    max_l = limits[1]

    color = Fore.WHITE
    
    while True:
        # 1. Generate a Float
        raw_value = random.uniform(min_l, max_l)
        
        # 2. Pack into 4 bytes (Big Endian Float)
        # '>f' means: Big-Endian (>), Float (f)
        data_bytes = struct.pack('>f', raw_value)

        # 3. Append sender timestamp (ms, uint32) for replay/skew checks
        sender_ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
        ts_bytes = struct.pack('>I', sender_ts_ms)
        full_data = data_bytes + ts_bytes

        msg = can.Message(
            arbitration_id=id,
            data=full_data,
            is_extended_id=False
        )

        try:
            bus.send(msg)
            
            print(
                f"{color}Node: {name} ({hex(id)})\n"
                f"Data: {raw_value:.6f}\n"  # Printing full precision
                f"Interval: {interval}s{Style.RESET_ALL}\n"
            )

            log_entry = {
                "timestamp": time.time(),
                "sender_ts_ms": sender_ts_ms,
                "id": hex(id),
                "name": name,
                "value": raw_value,
                "interval": interval
            }
            log_to_file(log_entry)

        except can.CanError:
            print(f"{Fore.RED}Error sending message for {name}{Style.RESET_ALL}")

        time.sleep(interval)

def send_sensors():
    print(f"Authorized nodes starting... Logging to: {LOG_FILE}")
    
    try:
        with open(INPUT_FILE, 'r') as f:
            valid_ids = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {INPUT_FILE}")
        sys.exit(1)

    try:
        for i in valid_ids:
            node_id = int(i['id'], 16) 
            node_name = i.get('name', 'Unknown')
            
            threading.Thread(
                target=sensors, 
                args=(node_id, node_name, i['interval'], i['limits']),
                daemon=True
            ).start()
                
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping sensors.")

if __name__ == "__main__":
    send_sensors()
