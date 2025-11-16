# ---------------------------------------------------------------------------
# GA-Unpacker
# Version: 1.0.0
# Author: Raxmatazz
# License: MIT
# #
# Description:
#   GA-Unpacker is an offline, dependency-free tool for decoding Google
#   Authenticator migration exports. It extracts Base32 TOTP secrets, names,
#   issuers, digits, type, and period values from the protobuf-based payload
#   contained in otpauth-migration:// URLs.
#
#   Google Authenticator exports data inside a URL-encoded, Base64-encoded,
#   binary protobuf message called MigrationPayload. This script manually
#   parses the protobuf fields (varints, length-delimited segments, and
#   embedded OtpParameters messages) without requiring any external protobuf
#   libraries.
#
#   Output is fully offline and never leaves your machine. Extracted secrets
#   are highly sensitive authentication material. Handle them securely.
#
# Notes:
#   - Requires Python 3.7+
#   - No external dependencies
#   - Fully offline operation
#   - Supports multiple accounts inside a single migration payload
#
# ---------------------------------------------------------------------------

#!/usr/bin/env python3
import sys
import base64
import urllib.parse

# ---------------------------------------------------------
# Protobuf helpers
# ---------------------------------------------------------

def read_varint(buf: bytes, idx: int):
    """Read a protobuf varint from buf[idx:], return (value, new_idx)."""
    result = 0
    shift = 0
    while True:
        if idx >= len(buf):
            raise ValueError("Incomplete varint")
        b = buf[idx]
        idx += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")
    return result, idx


def parse_length_delimited(buf: bytes, idx: int):
    """Read a length-delimited field (string / bytes / embedded message)."""
    length, new_idx = read_varint(buf, idx)
    end = new_idx + length
    if end > len(buf):
        raise ValueError("Length-delimited field extends beyond buffer")
    return buf[new_idx:end], end


# ---------------------------------------------------------
# MigrationPayload / OtpParameters parsing
# ---------------------------------------------------------

def parse_otp_parameters(sub: bytes):
    """
    Parse a single OtpParameters message and return a dict with the fields:
      secret (bytes)
      name   (str)
      issuer (str)
      digits (int or None)
      period (int or None)
      type   (int or None)
    Field numbers follow the known GA schema.
    """
    i = 0
    result = {
      "secret": None,
      "name": None,
      "issuer": None,
      "digits": None,
      "period": None,
      "type": None,
    }

    while i < len(sub):
        tag = sub[i]
        i += 1
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2:  # length-delimited
            value, i = parse_length_delimited(sub, i)
            if field_number == 1:       # bytes secret
                result["secret"] = value
            elif field_number == 2:     # string name
                result["name"] = value.decode("utf-8", errors="replace")
            elif field_number == 3:     # string issuer
                result["issuer"] = value.decode("utf-8", errors="replace")
            elif field_number in (4, 5, 7, 8):
                # algorithm, digits enum, type enum, issuer_int, etc. – we don't
                # need them as strings, but digits + period/type can come from enums
                # In GA’s schema, digits & type are enums stored as varints (wire_type=0),
                # so they won't appear here as length-delimited.
                pass
            else:
                # Unknown length-delimited field, just skip.
                pass

        elif wire_type == 0:  # varint
            value, i = read_varint(sub, i)
            if field_number == 5:       # digits (enum)
                # 0=unspecified, 1=6 digits, 2=8 digits etc. In practice GA uses 6.
                result["digits"] = value
            elif field_number == 6:     # counter (for HOTP)
                # We ignore for now.
                pass
            elif field_number == 7:     # type (enum)
                # 0=unspecified, 1=HOTP, 2=TOTP
                result["type"] = value
            elif field_number == 8:     # issuer_int
                pass
            else:
                # Other varints in OtpParameters: ignore.
                pass

        else:
            # We don't expect other wire types inside OtpParameters for this use.
            raise ValueError(f"Unsupported wire type {wire_type} in OtpParameters")

    return result


def extract_accounts_from_migration_url(url: str):
    """
    Parse a Google Authenticator otpauth-migration URL and return a list of
    account dicts:
      {
        "secret_b32": str,
        "name": str or None,
        "issuer": str or None,
        "digits": int or None,
        "period": int or None,
        "type": str or None
      }
    """
    if not url.startswith("otpauth-migration://"):
        raise ValueError("Input must start with 'otpauth-migration://'")

    if "?" not in url:
        raise ValueError("Missing '?data=' in URL")

    query = url.split("?", 1)[1]
    params = urllib.parse.parse_qs(query)
    if "data" not in params or not params["data"]:
        raise ValueError("Missing 'data=' parameter")

    data_param = params["data"][0]
    b64_str = urllib.parse.unquote(data_param)

    try:
        payload = base64.b64decode(b64_str)
    except Exception as e:
        raise ValueError(f"Invalid Base64 in data parameter: {e}")

    buf = payload
    idx = 0
    accounts = []

    # Known MigrationPayload fields:
    # 1: repeated OtpParameters otp_parameters
    # 2: int32 version
    # 3: int32 batch_size
    # 4: int32 batch_index
    # 5: int32 batch_id
    while idx < len(buf):
        tag = buf[idx]
        idx += 1
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            # OtpParameters
            sub_bytes, idx = parse_length_delimited(buf, idx)
            otp = parse_otp_parameters(sub_bytes)

            if otp["secret"] is None:
                # Skip entries without secret
                continue

            # Convert secret bytes to Base32 (for manual TOTP entry)
            secret_b32 = base64.b32encode(otp["secret"]).decode("ascii").rstrip("=")

            # GA's TOTP default: 6 digits, 30s
            # 'digits' and 'type' are enums; we try to interpret them nicely.
            digits_enum = otp["digits"]
            if digits_enum == 1:
                digits_val = 6
            elif digits_enum == 2:
                digits_val = 8
            else:
                digits_val = None

            type_enum = otp["type"]
            if type_enum == 1:
                type_str = "HOTP"
            elif type_enum == 2:
                type_str = "TOTP"
            else:
                type_str = None

            # period is defined at the MigrationPayload level in some schemas,
            # but in practice GA uses 30s for TOTP. We can safely default to 30
            # for TOTP, None otherwise.
            period = 30 if type_str == "TOTP" else None

            accounts.append({
                "secret_b32": secret_b32,
                "name": otp["name"],
                "issuer": otp["issuer"],
                "digits": digits_val,
                "period": period,
                "type": type_str,
            })

        elif wire_type == 0:
            # varint - version, batch_size, etc. We ignore them.
            _, idx = read_varint(buf, idx)
        elif wire_type == 2:
            # length-delimited - some unknown field; skip it.
            _, idx = parse_length_delimited(buf, idx)
        else:
            raise ValueError(f"Unsupported wire type {wire_type} in MigrationPayload")

    if not accounts:
        raise ValueError("No accounts (OtpParameters) found in migration payload")

    return accounts


# ---------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------

def main():
    if len(sys.argv) > 1:
        url = sys.argv[1].strip()
    else:
        url = input("otpauth-migration URL: ").strip()

    try:
        accounts = extract_accounts_from_migration_url(url)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Pretty-print all accounts
    for idx, acc in enumerate(accounts, start=1):
        print(f"Account #{idx}")
        print(f"  Name   : {acc['name'] or '(none)'}")
        print(f"  Issuer : {acc['issuer'] or '(none)'}")
        print(f"  Type   : {acc['type'] or '(unknown)'}")
        print(f"  Digits : {acc['digits'] or '(default)'}")
        print(f"  Period : {acc['period'] or '(default)'}")
        print(f"  Secret : {acc['secret_b32']}")
        print()

if __name__ == "__main__":
    main()
