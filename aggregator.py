import re
import requests
import ipaddress
from datetime import datetime

# Real public threat intelligence OSINT feeds (No API keys required)
FEEDS = {
    "URLHaus (Malicious URLs)": "https://abuse.ch",
    "Feodo Tracker (Botnet IPs)": "https://abuse.ch",
    "Tor Exit Nodes (High Risk)": "https://torproject.org"
}

# Strict regular expressions for parsing IOCs
REGEX_PATTERNS = {
    "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b',
    "url": r'https?://[^\s$\{\|\}\^\[\]`<>"\\]+',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b'
}

def validate_ip(ip_str):
    """Validates if parsed string is a legitimate public IP address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_private
    except ValueError:
        return False

def fetch_and_parse_feeds():
    """Downloads feeds, parses IOCs, normalizes data, and correlates records."""
    raw_iocs = []
    
    for feed_name, url in FEEDS.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                text = response.text
                
                # Extract by IOC type matching regex definitions
                for ioc_type, pattern in REGEX_PATTERNS.items():
                    matches = re.findall(pattern, text)
                    for match in matches:
                        # Direct normalization filter
                        if ioc_type == "ip" and not validate_ip(match):
                            continue
                        
                        raw_iocs.append({
                            "indicator": match.strip(),
                            "type": ioc_type.upper(),
                            "source": feed_name,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
        except Exception as e:
            print(f"Error fetching {feed_name}: {e}")
            
    return correlate_data(raw_iocs)

def correlate_data(raw_iocs):
    """Correlation Engine: Collapses duplicates, tallies overlapping sources, sets severity."""
    unique_iocs = {}
    
    for ioc in raw_iocs:
        ind = ioc["indicator"]
        if ind not in unique_iocs:
            unique_iocs[ind] = {
                "indicator": ind,
                "type": ioc["type"],
                "sources": {ioc["source"]},
                "timestamp": ioc["timestamp"]
            }
        else:
            unique_iocs[ind]["sources"].add(ioc["source"])
            
    # Calculate Severity Levels Based on Cross-Feed Correlation Frequency
    correlated_list = []
    for ind, data in unique_iocs.items():
        source_count = len(data["sources"])
        data["sources"] = ", ".join(data["sources"])
        data["feed_count"] = source_count
        
        if source_count >= 3:
            data["severity"] = "CRITICAL"
        elif source_count == 2:
            data["severity"] = "HIGH"
        else:
            data["severity"] = "MEDIUM" if data["type"] in ["URL", "IP"] else "LOW"
            
        correlated_list.append(data)
        
    return correlated_list
