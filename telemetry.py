import csv
import random
from datetime import datetime, timedelta

# Configuration & Constants
OUTPUT_FILE = "soc_threat_telemetry.csv"
NUM_RECORDS = 250

COUNTRIES = [
    ("United States", "US"), ("China", "CN"), ("Russia", "RU"), 
    ("Germany", "DE"), ("Brazil", "BR"), ("Netherlands", "NL"),
    ("North Korea", "KP"), ("Iran", "IR"), ("United Kingdom", "GB")
]

MITRE_TACTICS = [
    ("T1110", "Brute Force", "Credential Access"),
    ("T1566", "Phishing", "Initial Access"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
    ("T1071", "Application Layer Protocol", "Command and Control"),
    ("T1003", "OS Credential Dumping", "Credential Access")
]

INDICATOR_TYPES = ["IPv4", "Domain", "File Hash (SHA256)"]

def generate_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_hash():
    return "".join(random.choices("0123456789abcdef", k=64))

def generate_domain():
    domains = ["login-verify-update.com", "secure-account-auth.net", "update-m365-portal.org", "bad-actor-c2.xyz"]
    return random.choice(domains)

def main():
    print(f"[*] Generating {NUM_RECORDS} Threat Intelligence telemetry records...")
    
    fieldnames = [
        "timestamp", "indicator", "indicator_type", "country", "country_code",
        "abuse_confidence_score", "vt_malicious_count", "risk_level",
        "mitre_id", "mitre_technique", "mitre_tactic", "status"
    ]

    records = []
    base_time = datetime.utcnow() - timedelta(days=14)

    for i in range(NUM_RECORDS):
        # Time progression
        record_time = base_time + timedelta(minutes=random.randint(1, 20160))
        
        ind_type = random.choice(INDICATOR_TYPES)
        if ind_type == "IPv4":
            indicator = generate_ip()
        elif ind_type == "Domain":
            indicator = generate_domain()
        else:
            indicator = generate_hash()

        country, country_code = random.choice(COUNTRIES)
        
        # Risk & Threat Scores
        abuse_score = random.randint(0, 100)
        vt_malicious = random.randint(0, 75)

        # Calculate Risk Level based on scores
        if abuse_score > 75 or vt_malicious > 30:
            risk_level = "Critical"
            status = "Contained" if random.random() > 0.3 else "Active Investigation"
        elif abuse_score > 40 or vt_malicious > 10:
            risk_level = "High"
            status = "Investigating"
        elif abuse_score > 10 or vt_malicious > 2:
            risk_level = "Medium"
            status = "Monitored"
        else:
            risk_level = "Low"
            status = "Closed / False Positive"

        mitre_id, technique, tactic = random.choice(MITRE_TACTICS)

        records.append({
            "timestamp": record_time.strftime("%Y-%m-%d %H:%M:%S"),
            "indicator": indicator,
            "indicator_type": ind_type,
            "country": country,
            "country_code": country_code,
            "abuse_confidence_score": abuse_score,
            "vt_malicious_count": vt_malicious,
            "risk_level": risk_level,
            "mitre_id": mitre_id,
            "mitre_technique": technique,
            "mitre_tactic": tactic,
            "status": status
        })

    # Sort chronologically
    records.sort(key=lambda x: x["timestamp"])

    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Successfully exported SOC Telemetry dataset to '{OUTPUT_FILE}'!")

if __name__ == "__main__":
    main()