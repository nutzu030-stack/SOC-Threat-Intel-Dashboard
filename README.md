### SOC Threat Intelligence Telemetry Generator
A Python-based utility designed to simulate realistic Security Operations Center (SOC) threat intelligence telemetry and export it into structured CSV format. This dataset serves as a foundational data source for security dashboards, threat hunting practice, and SIEM data visualization labs.

### Features
Realistic Threat Simulation: Generates synthetic Indicators of Compromise (IoCs) including IPv4 addresses, domains, and SHA256 file hashes.

Framework Integration: Maps generated threats directly to the MITRE ATT&CK framework (Tactics and Techniques).

Security Scoring: Incorporates simulated metrics mirroring real-world threat feeds like AbuseIPDB (abuse_confidence_score) and VirusTotal (vt_malicious_count).

Automated Risk Categorization: Automatically assigns risk levels (Critical, High, Medium, Low) and investigation statuses based on threat scores.

Chronological Ordering: Sorts records sequentially across a 14-day timeline for realistic time-series data analysis.
Screenshot 2026-08-11 140645.png
screenshots/Screenshot 2026-08-17 131326.png
