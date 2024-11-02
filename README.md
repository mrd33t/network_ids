# Network Intrusion Detection System (NIDS)

This is a simple Network Intrusion Detection System (NIDS) implemented in Python using Scapy. It monitors network traffic and detects potential security threats such as port scans, ICMP floods, DNS amplification attacks, and ARP spoofing.

## Features

- TCP SYN flood detection
- ICMP flood detection
- DNS amplification attack detection
- ARP spoofing detection
- Configurable thresholds
- Logging with rotation

## Requirements

- Python 3.6+
- Root/Administrator privileges

## Installation

1. Clone this repository:
git clone https://github.com/mrd33t/network-ids.git
cd network-ids
2. Install the required packages:
scapy==2.5.0
netifaces==0.11.0

3. Choose the network interface you want to monitor when prompted.

4. The script will start monitoring network traffic and log any suspicious activities.

## Configuration

You can modify the `config.ini` file to adjust various settings:

- `SYN_THRESHOLD`: Number of SYN packets from a single IP to trigger an alert
- `ICMP_THRESHOLD`: Number of ICMP packets per minute to trigger an alert
- `REPORT_INTERVAL`: Number of packets between status updates
- `LOG_FILE`: Name of the log file
- `MAX_LOG_SIZE`: Maximum size of the log file before rotation (in bytes)
- `BACKUP_COUNT`: Number of backup log files to keep

## Disclaimer

This tool is for educational and testing purposes only. Always obtain proper authorization before monitoring network traffic that doesn't belong to you.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

