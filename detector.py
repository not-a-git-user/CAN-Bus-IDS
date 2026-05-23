import can
import argparse
import sys
import json
import redis
import struct # Required for unpacking floats
from colorama import Fore, Style, init
from collections import deque
import os

from crypto_utils import encrypt_data

DEFAULT_FILE = "telemetry_full_standardized.json"

parser = argparse.ArgumentParser()
parser.add_argument("--input_file", default=DEFAULT_FILE, help="Path to the telemetry JSON file")
parser.add_argument("--verbose", action="store_true", help="Print nominal data to CLI")
parser.add_argument("--redis", action="store_true", help="Publish data to Redis")
parser.add_argument("--encrypt", action="store_true", help="Encrypt JSON logs/Redis payloads")
parser.add_argument("--encrypt_key", default=os.getenv("CAN_ENCRYPTION_KEY"), help="Encryption key")
args = parser.parse_args()

valid_id_file = args.input_file
verbose_level = args.verbose
use_redis = args.redis
encryption_key = args.encrypt_key
use_encryption = args.encrypt or bool(encryption_key)

if use_encryption and not encryption_key:
    print("Error: encryption enabled but no key provided")
    sys.exit(1)


r_client = None
if use_redis:
    try:
        r_client = redis.Redis(host='localhost', port=6379, db=0)
        r_client.ping()
        print(f"{Fore.GREEN}[SYSTEM] Connected to Redis successfully.{Style.RESET_ALL}")
    except redis.ConnectionError:
        print(f"{Fore.RED}[SYSTEM] Error: Could not connect to Redis server.{Style.RESET_ALL}")
        sys.exit(1)

try:
    init()
    bus = can.interface.Bus(interface='socketcan', channel='vcan0', receive_own_messages=True)
except OSError:
    print("Can't bind to interface. Ensure vcan0 is up.")
    sys.exit(1)


# HELPER: Extract float from CAN message
def get_float_value(msg):
    try:
        # Unpack first 4 bytes as Big-Endian Float
        return struct.unpack('>f', msg.data[0:4])[0]
    except struct.error:
        return 0.0


def get_sender_ts_ms(msg):
    try:
        return struct.unpack('>I', msg.data[4:8])[0]
    except struct.error:
        return None

def export_alert(alert_type, msg, extra_data=None):
    alert_log = "alerts_live.json"
    val = get_float_value(msg)
    sender_ts_ms = get_sender_ts_ms(msg)
    
    alert_entry = {
        "timestamp": msg.timestamp,
        "sender_ts_ms": sender_ts_ms,
        "type": alert_type,
        "id": hex(msg.arbitration_id),
        "data_value": val,
        "extra": extra_data
    }
    
    with open(alert_log, "a") as f:
        if use_encryption:
            f.write(encrypt_data(alert_entry, encryption_key).decode("utf-8") + "\n")
        else:
            f.write(json.dumps(alert_entry) + "\n")

    if r_client:
        alert_entry["message"] = f"Alert: {alert_type} on ID {hex(msg.arbitration_id)}"
        if use_encryption:
            r_client.publish('alerts_encrypted', encrypt_data(alert_entry, encryption_key))
        else:
            r_client.publish('alerts', json.dumps(alert_entry))


class IDCheck():
    def __init__(self, valid_nodes):
        self.valid_nodes = valid_nodes

    def check(self, msg):
        if msg.arbitration_id not in self.valid_nodes:
            val = get_float_value(msg)
            print(
                f"{Fore.RED}ALERT:\nUnauthorized Node DETECTED \n"
                f"ID: {hex(msg.arbitration_id)} \n"
                f"Data: {val:.4f} {Style.RESET_ALL}\n"
                )
            export_alert("UNAUTHORIZED_NODE", msg)
            return False
        return True


def _is_older_ts(new_ts, last_ts):
    diff = (new_ts - last_ts) & 0xFFFFFFFF
    return diff > 0x7FFFFFFF


def _signed_diff(new_ts, old_ts):
    diff = (new_ts - old_ts) & 0xFFFFFFFF
    if diff & 0x80000000:
        return diff - 0x100000000
    return diff


class ReplayCheck():
    def __init__(self):
        self.last_ts = {}

    def check(self, msg):
        sender_ts = get_sender_ts_ms(msg)
        if sender_ts is None:
            return True

        last = self.last_ts.get(msg.arbitration_id)
        if last is not None:
            if sender_ts == last or _is_older_ts(sender_ts, last):
                val = get_float_value(msg)
                print(
                    f"{Fore.RED}ALERT:\nReplay DETECTED \n"
                    f"ID: {hex(msg.arbitration_id)} \n"
                    f"Data: {val:.4f} \n"
                    f"Sender TS: {sender_ts} (Last: {last}){Style.RESET_ALL}\n"
                )
                export_alert("REPLAY_DETECTED", msg, {"sender_ts_ms": sender_ts, "last_sender_ts_ms": last})
                return False

        self.last_ts[msg.arbitration_id] = sender_ts
        return True

class TimeCheck():
    def __init__(self, valid_nodes):
        self.valid_nodes = valid_nodes
        self.last_node_time = {}

    def check(self, msg):
        arb_id = msg.arbitration_id
        node_name = self.valid_nodes[arb_id].get('name', 'Unknown')
        current_time = msg.timestamp
        expected_interval = self.valid_nodes[arb_id]['interval']
        val = get_float_value(msg)
        is_safe = True

        if arb_id in self.last_node_time:
            t_delta= current_time - self.last_node_time[arb_id]
        
            if t_delta <  expected_interval * 0.8:
                export_alert("FLOODING", msg, {"delta": t_delta, "limit": expected_interval * 0.8})
                print(
                    f"{Fore.RED}ALERT:\nFlooding / Bus War DETECTED \n"
                    f"Sensor: {node_name} ({hex(arb_id)}) \n"
                    f"Data: {val:.4f}\n"
                    f"Delta: {t_delta:.4f}s (Limit: > {expected_interval * 0.8:.4f}s){Style.RESET_ALL}\n"
                )
                is_safe = False
                
            elif t_delta > expected_interval * 1.5:
                 print(
                    f"{Fore.RED}ALERT:\nMissing Slot / Timeout DETECTED \n"
                    f"Sensor: {node_name} ({hex(arb_id)}) \n"
                    f"Data: {val:.4f}\n"
                    f"Delta: {t_delta:.4f}s (Expected: {expected_interval}s){Style.RESET_ALL}\n"
                )
                 export_alert("MISSING_SLOT", msg, {"delta": t_delta, "limit": expected_interval * 1.5})
                 is_safe = False

        self.last_node_time[arb_id] = current_time
        return is_safe


class ClockSkewCheck():
    def __init__(self, valid_nodes):
        self.valid_nodes = valid_nodes
        self.samples = {}
        self.MAX_SKEW_MS = 5000
        self.JUMP_MS = 2000
        self.DRIFT_MS_PER_MIN = 200
        self.JITTER_MS = 250
        self.MAX_SAMPLES = 50

    def check(self, msg):
        arb_id = msg.arbitration_id
        if arb_id not in self.valid_nodes:
            return True

        sender_ts = get_sender_ts_ms(msg)
        if sender_ts is None:
            return True

        recv_ms = int(msg.timestamp * 1000) & 0xFFFFFFFF
        skew = _signed_diff(recv_ms, sender_ts)

        state = self.samples.setdefault(arb_id, deque(maxlen=self.MAX_SAMPLES))
        state.append((recv_ms, skew))

        reasons = []
        risk = "none"

        if len(state) >= 2:
            last_skew = state[-2][1]
            if abs(skew - last_skew) > self.JUMP_MS:
                reasons.append("jump_detected")

        if abs(skew) > self.MAX_SKEW_MS:
            reasons.append("skew_exceeded")

        drift_per_min = 0.0
        if len(state) >= 5:
            t0 = state[0][0]
            times = [t - t0 for t, _ in state]
            skews = [s for _, s in state]
            mean_t = sum(times) / len(times)
            mean_s = sum(skews) / len(skews)
            cov = sum((t - mean_t) * (s - mean_s) for t, s in zip(times, skews))
            var = sum((t - mean_t) ** 2 for t in times)
            if var > 0:
                slope_ms_per_ms = cov / var
                drift_per_min = slope_ms_per_ms * 60000.0
                if abs(drift_per_min) > self.DRIFT_MS_PER_MIN:
                    reasons.append("drift_detected")

        if len(state) >= 5:
            mean = sum(s for _, s in state) / len(state)
            variance = sum((s - mean) ** 2 for _, s in state) / len(state)
            jitter = variance ** 0.5
            if jitter > self.JITTER_MS:
                reasons.append("jitter_detected")

        if "skew_exceeded" in reasons:
            risk = "high"
        elif "jump_detected" in reasons or "drift_detected" in reasons:
            risk = "medium"
        elif "jitter_detected" in reasons:
            risk = "low"

        if risk in ("medium", "high"):
            node_name = self.valid_nodes[arb_id].get('name', 'Unknown')
            print(
                f"{Fore.YELLOW}ALERT:\nClock Skew Risk DETECTED \n"
                f"Sensor: {node_name} ({hex(arb_id)}) \n"
                f"Skew: {skew}ms Risk: {risk} Reasons: {reasons}{Style.RESET_ALL}\n"
            )
            export_alert(
                "CLOCK_SKEW_RISK",
                msg,
                {
                    "skew_ms": skew,
                    "risk": risk,
                    "reasons": reasons,
                    "drift_ms_per_min": drift_per_min,
                },
            )

        return True

class AllotedLimits():
    def __init__(self, valid_nodes):
        self.valid_nodes = valid_nodes

    def check(self, msg):
        arb_id = msg.arbitration_id
        limits = self.valid_nodes[arb_id]["limits"]
        node_name = self.valid_nodes[arb_id].get('name', 'Unknown')
        min_limit = limits[0]
        max_limit = limits[1]
        
        val = get_float_value(msg)

        if not (min_limit <= val <= max_limit):
            print(
                f"{Fore.RED}ALERT:\nRange Violation DETECTED \n"
                f"Sensor: {node_name} ({hex(arb_id)}) \n"
                f"Data: {val:.4f} (Allowed: {min_limit} to {max_limit}){Style.RESET_ALL}\n"
            )
            export_alert("RANGE_VIOLATION", msg, {"value": val, "limits": [min_limit, max_limit]})
            return False
            
        return True

class DeviationCheck():
    def __init__(self, valid_nodes):
        self.valid_nodes = valid_nodes
        self.stuck_counters = {} 
        self.MAX_STUCK_FRAMES = 5 

    def check(self, msg):
        arb_id = msg.arbitration_id
        if arb_id not in self.valid_nodes: return True 
        
        limits = self.valid_nodes[arb_id]["limits"]
        node_name = self.valid_nodes[arb_id].get('name', 'Unknown')
        min_limit = limits[0]
        max_limit = limits[1]
        
        val = get_float_value(msg)

        if arb_id not in self.stuck_counters:
            self.stuck_counters[arb_id] = 0

        # UPDATED: Pinned Logic for Floats
        # We check if value is within 1% of the top or bottom rail
        # This simulates a sensor shorting to power or ground
        total_range = max_limit - min_limit
        threshold = total_range * 0.01 

        is_pinned_high = (val >= max_limit - threshold)
        is_pinned_low = (val <= min_limit + threshold)

        if is_pinned_high or is_pinned_low:
            self.stuck_counters[arb_id] += 1
        else:
            self.stuck_counters[arb_id] = 0

        if self.stuck_counters[arb_id] > self.MAX_STUCK_FRAMES:
            print(
                f"{Fore.RED}ALERT: Deviation/Pinned Value DETECTED \n"
                f"Sensor: {node_name} ({hex(arb_id)}) \n"
                f"Value Stuck near limit: {val:.4f} for {self.stuck_counters[arb_id]} frames\n"
                f"{Style.RESET_ALL}"
            )
            export_alert("DEVIATION_STUCK", msg, {"stuck_value": val, "frames": self.stuck_counters[arb_id]})
            return False
            
        return True


def detect_node():
    with open(valid_id_file, encoding='utf-8') as f:
        data = json.load(f)

    valid_nodes = {int(node['id'], 16): node for node in data if 'id' in node}

    pipeline = [
        IDCheck(valid_nodes),
        ReplayCheck(),
        AllotedLimits(valid_nodes),
        DeviationCheck(valid_nodes),
        TimeCheck(valid_nodes),
        ClockSkewCheck(valid_nodes)
    ]

    print("Detection system begin:\n\n")

    try:
        for msg in bus:
            message_safe = True

            for rule in pipeline:
                if not rule.check(msg):
                    message_safe = False
                    break
            
            # Extract float for output
            val = get_float_value(msg)
            node_name = valid_nodes.get(msg.arbitration_id, {}).get('name', 'Unknown')

            if message_safe and verbose_level:
                # We simply hardcode Fore.GREEN here
                print(
                    f"{Fore.GREEN}NOMINAL: \nAuthorized Node Allowed, \n" 
                    f"Sensor: {node_name} ({hex(msg.arbitration_id)}), \n"
                    f"Data: {val:.6f} {Style.RESET_ALL}\n"
                )

            if message_safe and use_redis:
                telemetry_packet = {
                    "id": hex(msg.arbitration_id),
                    "name": node_name,
                    "value": val,
                    "status": "NOMINAL",
                    "timestamp": msg.timestamp,
                    "sender_ts_ms": get_sender_ts_ms(msg)
                }
                if use_encryption:
                    r_client.publish('telemetry_encrypted', encrypt_data(telemetry_packet, encryption_key))
                else:
                    r_client.publish('telemetry', json.dumps(telemetry_packet))

    except KeyboardInterrupt:
        print("\nKeyboard interrupt, Stopping detection system.")

if __name__ == "__main__":
    detect_node()
