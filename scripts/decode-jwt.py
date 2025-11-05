#!/usr/bin/env python3
"""
Pretty print JWT tokens by decoding header and payload.
Does NOT validate signatures - for debugging purposes only.
"""

import sys
import json
import base64


def decode_base64url(data):
    """Decode base64url encoded data."""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding

    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')

    return base64.b64decode(data)


def pretty_print_jwt(token):
    """Pretty print a JWT token."""
    try:
        # Split the token
        parts = token.strip().split('.')

        if len(parts) != 3:
            print("Error: Invalid JWT format. Expected 3 parts separated by dots.")
            return 1

        header_data = decode_base64url(parts[0])
        payload_data = decode_base64url(parts[1])

        header = json.loads(header_data)
        payload = json.loads(payload_data)

        print("=" * 80)
        print("JWT HEADER:")
        print("=" * 80)
        print(json.dumps(header, indent=2))
        print()

        print("=" * 80)
        print("JWT PAYLOAD:")
        print("=" * 80)
        print(json.dumps(payload, indent=2))
        print()

        print("=" * 80)
        print("JWT SIGNATURE (base64url encoded):")
        print("=" * 80)
        print(parts[2])
        print()

        return 0

    except Exception as e:
        print(f"Error decoding JWT: {e}", file=sys.stderr)
        return 1


def main():
    if len(sys.argv) < 2:
        print("Usage: decode-jwt.py <jwt-token>")
        print("   or: echo <jwt-token> | decode-jwt.py -")
        return 1

    if sys.argv[1] == '-':
        # Read from stdin
        token = sys.stdin.read().strip()
    else:
        token = sys.argv[1]

    return pretty_print_jwt(token)


if __name__ == "__main__":
    sys.exit(main())
