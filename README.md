# GA-Unpacker
GA-Unpacker is an offline, dependency-free tool that decodes Google Authenticator migration exports.
Google Authenticator stores exported accounts inside a URL-encoded, Base64-encoded, protobuf-encoded structure.
This script reverses that format and extracts TOTP secrets and metadata in plain, readable form.

## Overview

GA-Unpacker accepts migration URLs in the form:

otpauth-migration://offline?data=BASE64_URL_DATA

It extracts:

- Base32 TOTP secret
- Account name
- Issuer
- Type (TOTP or HOTP)
- Number of digits
- Period (usually 30 seconds)

Multiple accounts can be included in a single export.
All processing is fully local and offline.

## Features

- Fully offline operation
- No external dependencies
- No protobuf library required
- Supports multiple accounts
- Manually decodes protobuf fields
- Output compatible with all TOTP apps
- Works on Linux, macOS, and Windows

## Usage
Requires Python 3.7 or above.

### Method 1: Pass the URL as an argument

python GA-Unpacker.py "otpauth-migration://offline?data=..."

### Method 2: Interactive mode

python GA-Unpacker.py
otpauth-migration URL: <paste here>

## Example Output

Account #1
  Name   : ExampleAccount
  Issuer : ExampleCorp
  Type   : TOTP
  Digits : 6
  Period : 30
  Secret : IJAVESCPKIZUEVBWGVLVUR2DGNEFATKUJVAUEWCTINHFIWSWLBRT

## Technical Details

Google Authenticator exports data using several layers:

1. URL encoding
2. Base64 encoding
3. A binary protobuf message (MigrationPayload)
4. Embedded OtpParameters entries

Each OtpParameters block may contain:

- Secret bytes
- Account name
- Issuer
- Digits enum
- Type enum
- Optional HOTP counter

GA-Unpacker does not rely on any protobuf libraries.
The script manually parses:

- Varints
- Length-delimited fields
- Embedded messages
- Enum values

Finally, raw secret bytes are converted to RFC 4648 Base32 format,
which is required by TOTP applications.

## Security

- No network connections
- No telemetry
- No external dependencies
- Processing is entirely offline

Extracted secrets can be used to generate valid TOTP codes.
Treat them as highly sensitive information.

## Troubleshooting

Invalid Base64:
The exported URL may have been copied with extra characters. Copy it again from Google Authenticator.

No accounts found:
The migration export might be empty or incorrectly generated.

TOTP codes do not match:
Verify that you are using the Base32 secret output by this script,
not the raw internal ASCII shown inside the protobuf.

## License

MIT License.

## Contributions

Pull requests and suggestions are welcome.
