# tie-VirusTotal-File-Reputation
Checks the reputation of a file hash (MD5, SHA1, SHA256) against the VirusTotal API and returns the number of detections. - Focused on Augments existing log data or security events with threat intelligence data (e.g., geolocation of IP addresses, reputation scoring of URLs) to improve detection accuracy.

## Install
`git clone https://github.com/ShadowGuardAI/tie-virustotal-file-reputation`

## Usage
`./tie-virustotal-file-reputation [params]`

## Parameters
- `-h`: Show help message and exit
- `-k`: Your VirusTotal API key.  If not provided, the script will attempt to read it from the environment variable VIRUSTOTAL_API_KEY.
- `-f`: Instead of providing the hash directly, provide a file path to hash and submit to VirusTotal.
- `-w`: Wait time in seconds before retrying after a rate limit response (204 or 429). Retries are bounded at 3 attempts; after that the run reports the rate limit state and exits non-zero.
- `--timeout`: Timeout in seconds for the VirusTotal request (default: 30).

## Notes
The hash positional is optional when `-f` is used: provide either a hash or a file path, not both. Only the hash is sent to VirusTotal; the API key travels in the `x-apikey` header, never in the URL, and file bytes are never sent. A 404 response is reported as the hash not being found on VirusTotal. A 200 response without usable analysis stats is a run failure and exits non-zero. Hashes are validated as hexadecimal of length 32, 40, or 64 before any request is sent.

## License
Copyright (c) ShadowGuardAI
