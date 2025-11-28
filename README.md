# AWS-Day-48-Guardduty-Threat-Detection

Project Overview
Enabled AWS GuardDuty for intelligent threat detection and continuous security monitoring using machine learning and threat intelligence.

What I Did
* Enabled GuardDuty in my AWS account
* Configured multi-source threat monitoring:
  - VPC Flow Logs analysis
  - AWS CloudTrail event monitoring
  - DNS query logging
* Generated and analyzed sample security findings
* Reviewed threat intelligence and remediation steps
* Understood severity levels and finding types

Architecture
* Service: AWS GuardDuty
* Data Sources: CloudTrail, VPC Flow Logs, DNS Logs
* Detection: Machine Learning + Threat Intelligence
* Monitoring: 24/7 automated threat detection

Sample Findings Analyzed
* High Severity: Cryptocurrency mining detection
* Medium Severity: Unauthorized instance credential use
* Low Severity: Unusual API call patterns

Threat Categories Covered
1. Backdoor: Compromised instances
2. UnauthorizedAccess: Credential misuse
3. Trojan: Malware activity
4. Reconnaissance: Probing attacks
5. CryptoCurrency: Mining attempts

Skills Demonstrated
- Cloud Security Monitoring
- Threat Detection & Analysis
- Incident Response Preparation
- Security Information and Event Management (SIEM) concepts
- AWS Security Best Practices

What I Learned
- How GuardDuty uses ML for anomaly detection
- Different types of cloud security threats
- How to interpret security findings and severity levels
- Importance of proactive threat monitoring
- The value of threat intelligence feeds

Real-World Applications
- Detect compromised AWS credentials
- Identify cryptocurrency mining attempts
- Catch unusual data exfiltration
- Monitor for reconnaissance activity
- Alert on policy violations
