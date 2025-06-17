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
- `-w`: No description provided

## License
Copyright (c) ShadowGuardAI
