# CIS FortiGate 7.0.x Benchmark v1.4.0 – Rule Mapping

This document maps the controls currently implemented by the FortiGate CIS Benchmark Auditor.

The control set is based on the CIS FortiGate 7.0.x Benchmark v1.4.0.

Official CIS reference:

https://www.cisecurity.org/benchmark/fortinet

## Level 1 – 34 Controls

| Rule ID | Title |
|---|---|
| 1.1 | Ensure DNS server is configured |
| 1.2 | Ensure intra-zone traffic is restricted |
| 1.3 | Ensure management services are disabled on WAN port |
| 2.1.1 | Ensure Pre-Login Banner is set |
| 2.1.2 | Ensure Post-Login Banner is set |
| 2.1.3 | Ensure timezone is properly configured |
| 2.1.4 | Ensure correct system time is configured through NTP |
| 2.1.5 | Ensure hostname is set |
| 2.1.10 | Ensure management GUI listens on secure TLS version |
| 2.1.12 | Ensure single CPU core overloaded event is logged |
| 2.2.1 | Ensure Password Policy is enabled |
| 2.2.2 | Ensure administrator password retries and lockout are configured |
| 2.4.1 | Ensure default admin password is changed |
| 2.4.2 | Ensure all login accounts have specific trusted hosts enabled |
| 2.4.3 | Ensure administrator accounts have correct profiles assigned |
| 2.4.4 | Ensure idle timeout time is configured |
| 2.4.5 | Ensure only encrypted access channels are enabled |
| 2.4.6 | Ensure Local-in Policies are applied |
| 2.4.7 | Ensure default Admin ports are changed |
| 2.4.8 | Virtual patching on the local-in management interface |
| 2.5.2 | Ensure HA monitor interfaces are configured |
| 2.5.3 | Ensure HA Reserved Management Interface is Configured |
| 3.2 | Ensure policies do not use ALL as Service |
| 3.3 | Ensure Tor and malicious traffic is blocked using ISDB |
| 3.4 | Ensure logging is enabled on all firewall policies |
| 4.1.2 | Ensure IPS Security Profile is applied to policies |
| 4.2.6 | Ensure inline scanning with sandbox is enabled |
| 4.3.2 | Ensure logging is enabled on DNS Filter |
| 4.3.3 | Apply DNS Filter Security Profile to Policies |
| 4.4.1 | Block high risk categories on Application Control |
| 4.4.3 | Ensure Application Control Security Profile is applied |
| 4.4.4 | Apply Application Control Security Profile to Policies |
| 5.1.1 | Ensure Compromised Host Quarantine is enabled |
| 7.2.1 | Ensure logs sent to FortiAnalyzer/FortiManager are encrypted |

## Level 2 – 22 Controls

| Rule ID | Title |
|---|---|
| 2.1.6 | Ensure the latest firmware is installed |
| 2.1.7 | Ensure USB firmware and configuration installation is disabled |
| 2.1.8 | Ensure static keys for TLS are disabled |
| 2.1.9 | Ensure Global Strong Encryption is enabled |
| 2.1.11 | Ensure CDN is enabled for improved GUI performance |
| 2.3.1 | Ensure only SNMPv3 is enabled |
| 2.3.2 | Ensure SNMPv3 trusted hosts are configured |
| 2.5.1 | Ensure HA configuration is configured |
| 3.1 | Ensure that unused policies are reviewed regularly |
| 4.1.1 | Ensure Botnet connections are detected |
| 4.2.1 | Ensure Antivirus Definition Push Updates are configured |
| 4.2.2 | Apply Antivirus Security Profile to Policies |
| 4.2.3 | Ensure Outbreak Prevention Database is enabled |
| 4.2.4 | Ensure AI/heuristic-based malware detection is enabled |
| 4.2.5 | Ensure Grayware detection on antivirus is enabled |
| 4.3.1 | Ensure Botnet C&C Domain Blocking DNS Filter is enabled |
| 4.4.2 | Ensure logging is enabled on Application Control |
| 5.2.1.1 | Ensure Security Fabric is configured |
| 6.1.1 | Ensure trusted signed certificate is used for VPN portal |
| 6.1.2 | Ensure limited TLS versions for SSL VPN |
| 7.1.1 | Ensure Event Logging is enabled |
| 7.3.1 | Ensure Centralized Logging and Reporting (Syslog) is enabled |

## Control Count

- Level 1: 34 controls
- Level 2: 22 controls
- Total: 56 controls

## Important Note

This mapping documents the control set currently implemented by this auditor. It does not claim that CIS publishes a separate benchmark for every FortiOS release.

The auditor has been tested with FortiOS 7.0.x and 7.6.x configurations while using this benchmark control set.
