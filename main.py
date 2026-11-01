#!/usr/bin/env python3

import argparse
import hashlib
import logging
import os
import sys
import time

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Checks the reputation of a file hash (MD5, SHA1, SHA256) against the VirusTotal API."
    )
    parser.add_argument(
        "hash",
        nargs="?",
        default=None,
        help="The file hash (MD5, SHA1, or SHA256) to check against VirusTotal. Omit when -f/--file is given.",
    )
    parser.add_argument(
        "-k",
        "--api_key",
        help="Your VirusTotal API key.  If not provided, the script will attempt to read it from the environment variable VIRUSTOTAL_API_KEY.",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Instead of providing the hash directly, provide a file path to hash and submit to VirusTotal.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for the VirusTotal request (default: 30).",
    )
    parser.add_argument(
        "-w",
        "--wait_time",
        type=int,
        default=15,
        help="Wait time in seconds before retrying after exceeding rate limits (default: 15).  VirusTotal public API is limited to 4 requests per minute.",
    )
    return parser


def calculate_hash(file_path, hash_type="sha256"):
    """Calculates the hash of a file."""
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()

        if hash_type == "md5":
            file_hash = hashlib.md5(file_content).hexdigest()
        elif hash_type == "sha1":
            file_hash = hashlib.sha1(file_content).hexdigest()
        elif hash_type == "sha256":
            file_hash = hashlib.sha256(file_content).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")

        return file_hash

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error calculating hash: {e}")
        return None


def check_file_reputation(file_hash, api_key, wait_time=15, timeout=30, max_retries=3):
    """
    Checks the reputation of a file hash against the VirusTotal API.

    Returns:
        tuple: (outcome, data) where outcome is one of "success",
        "not_found", "rate_limited", or "error". Data is the parsed
        response on success, otherwise None.
    """
    url = "https://www.virustotal.com/api/v3/files/" + file_hash
    headers = {"x-apikey": api_key}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error: {e}")
            return "error", None

        if response.status_code == 200:
            try:
                return "success", response.json()
            except ValueError as e:
                logging.error(f"Error decoding VirusTotal response: {e}")
                return "error", None
        elif response.status_code == 404:
            logging.info(f"File with hash {file_hash} not found on VirusTotal.")
            return "not_found", None
        elif response.status_code in (204, 429):
            logging.warning(
                f"Rate limit response (HTTP {response.status_code}) on attempt {attempt} of {max_retries}."
            )
            if attempt < max_retries:
                time.sleep(wait_time)
                continue
            logging.error("Rate limit persisted after all retries.")
            return "rate_limited", None
        else:
            logging.error(f"Error: HTTP {response.status_code}")
            return "error", None
    return "rate_limited", None


def main():
    """
    Main function to execute the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Attempt to get the API key from the environment variable if not provided
    api_key = args.api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    if not api_key:
        logging.error(
            "VirusTotal API key not provided. Please provide it via the -k/--api_key argument or set the VIRUSTOTAL_API_KEY environment variable."
        )
        sys.exit(1)

    if args.file and args.hash:
        parser.error("Provide either a hash or -f/--file, not both.")
    if not args.file and not args.hash:
        parser.error("Provide a file hash, or use -f/--file to hash a local file.")

    file_hash = args.hash
    if args.file:
        file_hash = calculate_hash(args.file, "sha256")
        if file_hash is None:
            sys.exit(1)  # Exit if hash calculation failed

    if not file_hash:
        logging.error("File hash not provided.")
        sys.exit(1)

    # Validate the input hash: correct length and hexadecimal only.
    if len(file_hash) not in (32, 40, 64) or any(
        c not in "0123456789abcdefABCDEF" for c in file_hash
    ):
        logging.error(
            "Invalid hash format.  Please provide a hexadecimal MD5 (32 characters), SHA1 (40 characters), or SHA256 (64 characters) hash."
        )
        sys.exit(1)

    # Check the file reputation
    outcome, result = check_file_reputation(
        file_hash, api_key, args.wait_time, timeout=args.timeout
    )

    if outcome == "not_found":
        print(f"File with hash {file_hash} not found on VirusTotal.")
        return
    if outcome == "rate_limited":
        logging.error(
            "VirusTotal rate limit persisted after bounded retries; no reputation result was retrieved."
        )
        sys.exit(1)
    if outcome != "success" or not result:
        logging.error("Failed to retrieve file reputation from VirusTotal.")
        sys.exit(1)

    data = result.get("data") if isinstance(result, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    if not isinstance(stats, dict) or not all(
        key in stats for key in ("malicious", "harmless", "suspicious", "undetected")
    ):
        logging.error(
            f"Malformed VirusTotal response for hash {file_hash}: no usable last_analysis_stats. Run failed."
        )
        sys.exit(1)
    print(f"File Hash: {file_hash}")
    print(f"Detections: {stats['malicious']}")
    print(f"Harmless: {stats['harmless']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Undetected: {stats['undetected']}")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check the reputation of a file hash:
#    python tie-VirusTotal-File-Reputation.py <file_hash> -k <api_key>
# 2. Check the reputation of a file hash, reading API key from environment variable:
#    VIRUSTOTAL_API_KEY=<api_key> python tie-VirusTotal-File-Reputation.py <file_hash>
# 3. Check the reputation of a file by providing the file path:
#    python tie-VirusTotal-File-Reputation.py -f <file_path> -k <api_key>
# 4. Check the reputation of a file by providing the file path, reading API key from environment variable, and setting wait time:
#    VIRUSTOTAL_API_KEY=<api_key> python tie-VirusTotal-File-Reputation.py -f <file_path> -w 30