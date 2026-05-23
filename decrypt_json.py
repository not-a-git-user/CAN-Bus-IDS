import argparse
import json
import os
import sys

from crypto_utils import decrypt_data, is_encrypted_envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", required=True, help="Path to encrypted JSONL file")
    parser.add_argument("--output_file", help="Optional output file for decrypted JSONL")
    parser.add_argument("--key", default=os.getenv("CAN_ENCRYPTION_KEY"), help="Decryption key")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON objects")
    args = parser.parse_args()

    if not args.key:
        print("Error: decryption key required via --key or CAN_ENCRYPTION_KEY", file=sys.stderr)
        return 1

    out_fh = open(args.output_file, "w") if args.output_file else None
    indent = 2 if args.pretty else None

    with open(args.input_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(obj, dict) and is_encrypted_envelope(obj):
                try:
                    decrypted = decrypt_data(json.dumps(obj).encode("utf-8"), args.key)
                except ValueError as exc:
                    print(f"Decrypt failed: {exc}", file=sys.stderr)
                    continue
                output = json.dumps(decrypted, indent=indent, sort_keys=True)
            else:
                output = json.dumps(obj, indent=indent, sort_keys=True)

            if out_fh:
                out_fh.write(output + "\n")
            else:
                print(output)

    if out_fh:
        out_fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
