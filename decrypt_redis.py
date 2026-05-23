import argparse
import json
import os
import sys

import redis

from crypto_utils import decrypt_data, is_encrypted_envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost", help="Redis host")
    parser.add_argument("--port", type=int, default=6379, help="Redis port")
    parser.add_argument("--db", type=int, default=0, help="Redis DB")
    parser.add_argument(
        "--channels",
        default="alerts_encrypted,telemetry_encrypted",
        help="Comma-separated channels to subscribe to",
    )
    parser.add_argument("--key", default=os.getenv("CAN_ENCRYPTION_KEY"), help="Decryption key")
    args = parser.parse_args()

    if not args.key:
        print("Error: decryption key required via --key or CAN_ENCRYPTION_KEY", file=sys.stderr)
        return 1

    client = redis.Redis(host=args.host, port=args.port, db=args.db)
    try:
        client.ping()
    except redis.ConnectionError:
        print("Error: could not connect to Redis", file=sys.stderr)
        return 1

    channels = [c.strip() for c in args.channels.split(",") if c.strip()]
    pubsub = client.pubsub()
    pubsub.subscribe(*channels)

    print(f"Subscribed to: {', '.join(channels)}")
    for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        raw = message.get("data")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            print(raw)
            continue

        if isinstance(obj, dict) and is_encrypted_envelope(obj):
            try:
                decrypted = decrypt_data(json.dumps(obj).encode("utf-8"), args.key)
            except ValueError as exc:
                print(f"Decrypt failed: {exc}", file=sys.stderr)
                continue
            print(json.dumps(decrypted, sort_keys=True))
        else:
            print(json.dumps(obj, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
