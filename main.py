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
        help="The file hash (MD5, SHA1, or SHA256) to check against VirusTotal.",
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


def check_file_reputation(file_hash, api_key, wait_time=15):
    """
    Checks the reputation of a file hash against the VirusTotal API.

    Args:
        file_hash (str): The file hash (MD5, SHA1, or SHA256).
        api_key (str): Your VirusTotal API key.
        wait_time (int): Wait time in seconds before retrying after exceeding rate limits.

    Returns:
        dict: A dictionary containing the VirusTotal API response, or None on error.
    """
    url = "https://www.virustotal.com/api/v3/files/" + file_hash
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            logging.warning("Rate limit exceeded. Waiting and retrying...")
            time.sleep(wait_time)
            return check_file_reputation(file_hash, api_key, wait_time)  # Retry
        elif response.status_code == 404:
            logging.info(f"File with hash {file_hash} not found on VirusTotal.")
            return None
        else:
            logging.error(
                f"Error: HTTP {response.status_code} - {response.text}"
            )
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


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

    file_hash = args.hash
    if args.file:
        file_hash = calculate_hash(args.file, "sha256")
        if file_hash is None:
            sys.exit(1)  # Exit if hash calculation failed

    if not file_hash:
        logging.error("File hash not provided.")
        sys.exit(1)

    # Validate the input hash
    if not (
        len(file_hash) == 32
        or len(file_hash) == 40
        or len(file_hash) == 64
    ):
        logging.error(
            "Invalid hash format.  Please provide an MD5 (32 characters), SHA1 (40 characters), or SHA256 (64 characters) hash."
        )
        sys.exit(1)

    # Check the file reputation
    result = check_file_reputation(file_hash, api_key, args.wait_time)

    if result:
        if "data" in result and "attributes" in result["data"]:
            stats = result["data"]["attributes"]["last_analysis_stats"]
            print(f"File Hash: {file_hash}")
            print(f"Detections: {stats['malicious']}")
            print(f"Harmless: {stats['harmless']}")
            print(f"Suspicious: {stats['suspicious']}")
            print(f"Undetected: {stats['undetected']}")
        else:
            logging.warning(f"No scan results available for hash {file_hash}")

    else:
        logging.error("Failed to retrieve file reputation from VirusTotal.")
        sys.exit(1)


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