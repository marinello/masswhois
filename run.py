import ipaddress
import whois
import socket
from collections import Counter
import sys
from typing import Dict, List, Tuple

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def get_whois_info(ip: str) -> Tuple[str, str]:
    """
    Get WHOIS information for an IP address.
    Returns a tuple of (owner, country).
    """
    try:
        w = whois.whois(ip)
        # Some WHOIS responses might have different field names
        owner = w.org or w.registrar or w.name or "Unknown"
        country = w.country or "Unknown"
        
        # Clean up the data
        if isinstance(owner, list):
            owner = owner[0]
        if isinstance(country, list):
            country = country[0]
            
        return owner.strip(), country.strip()
    except Exception as e:
        print(f"Error getting WHOIS info for {ip}: {str(e)}", file=sys.stderr)
        return "Unknown", "Unknown"

def process_ip_list(filename: str) -> Dict[str, int]:
    """
    Process a file containing IP addresses and return country statistics.
    """
    country_stats = Counter()
    total_ips = 0
    processed_ips = 0
    
    try:
        with open(filename, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]
            total_ips = len(ip_list)
            
            for ip in ip_list:
                if validate_ip(ip):
                    owner, country = get_whois_info(ip)
                    if country != "Unknown":
                        country_stats[country] += 1
                    processed_ips += 1
                    print(f"Processed: {ip} | Owner: {owner} | Country: {country}")
                else:
                    print(f"Invalid IP address: {ip}", file=sys.stderr)
                    
    except FileNotFoundError:
        print(f"Error: File {filename} not found", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"Error processing file: {str(e)}", file=sys.stderr)
        return {}
    
    print(f"\nProcessing complete!")
    print(f"Total IPs: {total_ips}")
    print(f"Successfully processed: {processed_ips}")
    
    return dict(country_stats)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <ip_list_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    country_stats = process_ip_list(filename)
    
    if country_stats:
        print("\nCountry Statistics:")
        print("-" * 30)
        for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"{country}: {count} IP(s)")

if __name__ == "__main__":
    main()