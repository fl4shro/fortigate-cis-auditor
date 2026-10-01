"""
CIS FortiGate Benchmark v1.4.0 – Level 2 Rules
=================================================
Level 2 rules represent advanced security settings intended for
high-security environments. They may impact functionality or performance.

CIS Sections covered:
  2.1.x  – Advanced System Settings
  2.4.x  – Advanced Admin Access
  3.x    – Advanced Firewall Policy
  4.x    – Advanced Security Profiles
  5.x    – Advanced Security Fabric
  6.x    – VPN Configuration
  7.x    – Advanced Logging
"""

import re
from typing import List
from cis_benchmark.rules.base import (
    CISRule, CallableCISRule, RuleResult, CISLevel, RuleSeverity,
)


# =============================================================================
# Rule Evaluator Functions
# =============================================================================

def _eval_firmware_latest(rule, config):
    """Manual check – firmware version cannot be validated offline."""
    if config.version:
        return rule._make_result(True, f"FortiOS version: {config.version} (manual verification needed)")
    return rule._make_result(False, "FortiOS version not detected")


def _eval_admin_https_ssl(rule, config):
    val = config.get_global_setting("admin-https-ssl-versions", "")
    if "tlsv1-2" in val.lower() or "tlsv1-3" in val.lower():
        if "tlsv1-0" not in val.lower() and "sslv3" not in val.lower():
            return rule._make_result(True, f"TLS versions: {val}")
    return rule._make_result(False, f"admin-https-ssl-versions: {val or 'not set'}")


def _eval_local_in_policies(rule, config):
    if config.search(r'config firewall local-in-policy'):
        return rule._make_result(True, "Local-in policies configured")
    return rule._make_result(False, "Local-in policies not configured")


def _eval_default_admin_ports(rule, config):
    admin_port = config.get_global_setting("admin-port", "80")
    admin_sport = config.get_global_setting("admin-sport", "443")
    ssh_port = config.get_global_setting("admin-ssh-port", "22")
    issues = []
    if admin_port == "80":
        issues.append(f"HTTP port={admin_port}")
    if admin_sport == "443":
        issues.append(f"HTTPS port={admin_sport}")
    if ssh_port == "22":
        issues.append(f"SSH port={ssh_port}")
    if not issues:
        return rule._make_result(True, f"Custom ports: HTTP={admin_port}, HTTPS={admin_sport}, SSH={ssh_port}")
    return rule._make_result(False, f"Default ports in use: {', '.join(issues)}")


def _eval_ssl_vpn_tls(rule, config):
    if config.search(r'config vpn ssl settings'):
        val = config.search_value(r'set\s+ssl-min-proto-ver\s+(\S+)')
        if val and val.lower() in ["tls1-2", "tlsv1-2", "tls1-3", "tlsv1-3"]:
            return rule._make_result(True, f"SSL VPN minimum TLS: {val}")
        return rule._make_result(False, f"SSL VPN TLS version: {val or 'not restricted'}")
    return rule._make_result(False, "SSL VPN not configured")


def _eval_vpn_certificate(rule, config):
    if config.search(r'config vpn certificate'):
        if config.search(r'set\s+certificate\s+"(?!Fortinet_Factory)'):
            return rule._make_result(True, "Custom VPN certificate configured")
        return rule._make_result(False, "Factory default certificate in use for VPN")
    return rule._make_result(False, "VPN certificate not configured")


def _eval_ssl_inspection(rule, config):
    if config.search(r'config firewall ssl-ssh-profile'):
        return rule._make_result(True, "SSL/SSH inspection profiles configured")
    return rule._make_result(False, "SSL/SSH inspection not configured")


def _eval_web_filtering(rule, config):
    if config.search(r'config webfilter profile|set\s+webfilter-profile'):
        return rule._make_result(True, "Web filtering configured")
    return rule._make_result(False, "Web filtering not configured")


def _eval_dnssec(rule, config):
    if config.search(r'set\s+dnssec\s+enable'):
        return rule._make_result(True, "DNSSEC validation enabled")
    return rule._make_result(False, "DNSSEC not enabled")


def _eval_sandbox_inspection(rule, config):
    if config.search(r'config system fortisandbox|set\s+sandbox'):
        return rule._make_result(True, "Integração com Sandbox configurada")
    return rule._make_result(False, "Sandbox not configured")


def _eval_vpn_ipsec_encryption(rule, config):
    if config.search(r'config vpn ipsec phase1'):
        if config.search(r'set\s+proposal\s+.*aes256'):
            return rule._make_result(True, "IPsec Phase 1 uses AES-256 encryption")
        proposal = config.search_value(r'set\s+proposal\s+(.+?)$')
        return rule._make_result(False, f"IPsec encryption: {proposal or 'not AES-256'}")
    return rule._make_result(False, "IPsec VPN not configured")


def _eval_vpn_ipsec_dh_group(rule, config):
    if config.search(r'config vpn ipsec phase1'):
        if config.search(r'set\s+dhgrp\s+.*(?:14|19|20|21)'):
            return rule._make_result(True, "IPsec uses strong DH group (≥14)")
        return rule._make_result(False, "IPsec DH group may be weak")
    return rule._make_result(False, "IPsec VPN not configured")


def _eval_log_encryption(rule, config):
    if config.search(r'set\s+enc-algorithm\s+(?:high|aes256)'):
        return rule._make_result(True, "Log encryption enabled")
    return rule._make_result(False, "Log encryption not configured")




def _eval_tor_isdb_blocking(rule, config):
    """
    CIS 3.3

    Ensure firewall policy denying all traffic to/from
    Tor, malicious server, or scanner IP addresses using ISDB.

    Avaliação feita diretamente no raw_content do FortiGate,
    pois o show full-configuration contém campos de ISDB
    de origem e destino que podem não ser corretamente
    expostos pelo parser estruturado.
    """

    raw = getattr(config, "raw_content", "")

    if not isinstance(raw, str) or not raw.strip():
        return rule._make_result(
            False,
            "FAIL: conteúdo bruto da configuração não disponível"
        )

    lines = raw.splitlines()

    # --------------------------------------------------------
    # Localizar config firewall policy
    # --------------------------------------------------------

    start = None

    for i, line in enumerate(lines):
        if line.strip().lower() == "config firewall policy":
            start = i
            break

    if start is None:
        return rule._make_result(
            False,
            "FAIL: config firewall policy não encontrada"
        )

    policy_lines = []

    base_indent = len(lines[start]) - len(lines[start].lstrip())

    for line in lines[start + 1:]:

        stripped = line.strip()

        if stripped.lower() == "end":
            break

        policy_lines.append(line)

    # --------------------------------------------------------
    # Dividir em policies
    # --------------------------------------------------------

    policies = []

    current = None

    for line in policy_lines:

        stripped = line.strip()

        m = re.match(
            r'^edit\s+(.+)$',
            stripped,
            re.I
        )

        if m:

            if current is not None:
                policies.append(current)

            current = {
                "id": m.group(1).strip().strip('"'),
                "lines": []
            }

            continue

        if stripped.lower() == "next":

            if current is not None:
                policies.append(current)

            current = None
            continue

        if current is not None:
            current["lines"].append(line)

    if current is not None:
        policies.append(current)

    # --------------------------------------------------------
    # Procurar policy DENY + ISDB
    # --------------------------------------------------------

    tor_objects = (
        "Tor-Tor.Node",
        "Tor-Exit.Node",
        "Tor-Relay.Node",
    )

    other_objects = (
        "Malicious-Malicious.Server",
        "Botnet-C&C.Server",
        "Scanner-",
    )

    found = []

    for policy in policies:

        block = "\n".join(policy["lines"])

        # Policy precisa estar habilitada.
        status_match = re.search(
            r'^\s*set\s+status\s+(\S+)',
            block,
            re.I | re.M
        )

        status = (
            status_match.group(1).strip().lower()
            if status_match
            else "enable"
        )

        if status not in ("enable", "enabled"):
            continue

        # Precisa ser DENY.
        action_match = re.search(
            r'^\s*set\s+action\s+deny\s*$',
            block,
            re.I | re.M
        )

        if not action_match:
            continue

        # ----------------------------------------------------
        # ISDB destino
        # ----------------------------------------------------

        dst_enable = re.search(
            r'^\s*set\s+internet-service\s+enable\s*$',
            block,
            re.I | re.M
        )

        dst_names = re.search(
            r'^\s*set\s+internet-service-name\s+(.+)$',
            block,
            re.I | re.M
        )

        if dst_enable and dst_names:

            names = dst_names.group(1)

            matched = []

            for obj in tor_objects + other_objects:
                if obj.lower() in names.lower():
                    matched.append(obj)

            if matched:
                policy_id = str(policy["id"]).strip()

                if policy_id and policy_id not in found:
                    found.append(policy_id)

                continue

        # ----------------------------------------------------
        # ISDB origem
        # ----------------------------------------------------

        src_enable = re.search(
            r'^\s*set\s+internet-service-src\s+enable\s*$',
            block,
            re.I | re.M
        )

        src_names = re.search(
            r'^\s*set\s+internet-service-src-name\s+(.+)$',
            block,
            re.I | re.M
        )

        if src_enable and src_names:

            names = src_names.group(1)

            matched = []

            for obj in tor_objects + other_objects:
                if obj.lower() in names.lower():
                    matched.append(obj)

            if matched:
                policy_id = str(policy["id"]).strip()

                if policy_id and policy_id not in found:
                    found.append(policy_id)

    # --------------------------------------------------------
    # Resultado
    # --------------------------------------------------------

    if found:

        return rule._make_result(
            True,
            "PASS: policies DENY utilizando ISDB detectadas: " +
            ", ".join(found)
        )

    return rule._make_result(
        False,
        "FAIL: nenhuma policy DENY utilizando ISDB "
        "para Tor, malicious server ou scanner foi detectada"
    )

def _eval_botnet_detection(rule, config):
    if config.search(r'set\s+scan-botnet-connections\s+(?:block|monitor)'):
        return rule._make_result(True, "Detecção de conexões Botnet habilitada")
    return rule._make_result(False, "Botnet connection scanning not enabled")


def _eval_dns_filter_logging(rule, config):
    if config.search(r'config dnsfilter profile|config dns-filter profile'):
        if config.search(r'set\s+log-all-domain\s+enable'):
            return rule._make_result(True, "DNS filter logging enabled")
        return rule._make_result(False, "DNS filter logging not fully enabled")
    return rule._make_result(False, "DNS filter not configured")


def _eval_app_control_logging(rule, config):
    if config.search(r'config application list'):
        return rule._make_result(True, "Application control configured")
    return rule._make_result(False, "Application control not configured")


def _eval_high_risk_categories(rule, config):
    if config.search(r'config webfilter profile'):
        if config.search(r'set\s+action\s+block'):
            return rule._make_result(True, "Web filter blocking rules configured")
        return rule._make_result(False, "Web filter configured but no blocking rules")
    return rule._make_result(False, "Web filtering not configured")


def _eval_content_disarm(rule, config):
    if config.search(r'config firewall profile-protocol-options'):
        if config.search(r'set\s+content-disarm-reconstruct\s+enable|config content-disarm'):
            return rule._make_result(True, "Content Disarm & Reconstruction enabled")
        return rule._make_result(False, "CDR not explicitly enabled")
    return rule._make_result(False, "Protocol options not configured")


def _eval_email_filter(rule, config):
    if config.search(r'config emailfilter profile|config spamfilter profile'):
        return rule._make_result(True, "Email filtering configured")
    return rule._make_result(False, "Email filtering not configured")


def _eval_file_filter(rule, config):
    if config.search(r'config file-filter profile'):
        return rule._make_result(True, "File filtering configured")
    return rule._make_result(False, "File filtering not configured")


# =============================================================================
# Rule Definitions
# =============================================================================

def get_level2_rules() -> List[CISRule]:
    """Return all CIS Level 2 rules."""
    L2 = CISLevel.LEVEL_2

    rules = [
        # --- 2.1.x Advanced System Settings ---
        CallableCISRule(
            _eval_firmware_latest,
            rule_id="2.1.6",
            title="Ensure the latest firmware is installed",
            level=L2, severity=RuleSeverity.HIGH,
            description="Running latest firmware ensures all security patches are applied.",
            expected_value="Latest FortiOS version",
            remediation="Update to the latest stable FortiOS firmware",
            category="System", cis_section="2.1.6",
            remediation_cli="execute restore image tftp <firmware_file> <tftp_server>",
        ),

        # --- 2.4.x Advanced Admin Access ---
        CallableCISRule(
            _eval_local_in_policies,
            rule_id="2.4.6",
            title="Ensure Local-in Policies are applied",
            level=L2, severity=RuleSeverity.HIGH,
            description="Local-in policies control traffic destined to the FortiGate itself.",
            expected_value="Local-in policies configured",
            remediation="Configure local-in policies to restrict management traffic",
            category="Admin", cis_section="2.4.6",
            remediation_cli="config firewall local-in-policy\n  edit 1\n    set intf <interface>\n    set srcaddr <allowed_hosts>\n    set dstaddr all\n    set action accept\n    set service <mgmt_services>\n    set schedule always\n  next\nend",
        ),
        CallableCISRule(
            _eval_default_admin_ports,
            rule_id="2.4.7",
            title="Ensure default Admin ports are changed",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="Changing default admin ports reduces automated scanning attacks.",
            expected_value="Non-default admin ports",
            remediation="Change HTTP, HTTPS, and SSH admin ports from defaults",
            category="Admin", cis_section="2.4.7",
            remediation_cli="config system global\n  set admin-port 8080\n  set admin-sport 8443\n  set admin-ssh-port 2222\nend",
        ),

        # --- 3.x Advanced Firewall Policy ---
        CallableCISRule(
            _eval_tor_isdb_blocking,
            rule_id="3.3",
            title="Ensure Tor and malicious traffic is blocked using ISDB",
            level=L2, severity=RuleSeverity.HIGH,
            description="Block known Tor exit nodes and malicious IP databases.",
            expected_value="Tor/malicious ISDB blocking configured",
            remediation="Create deny policy using Internet Service Database for Tor",
            category="Firewall", cis_section="3.3",
            remediation_cli="config firewall policy\n  edit <id>\n    set internet-service enable\n    set internet-service-id <tor_isdb_id>\n    set action deny\n  next\nend",
        ),

        # --- 4.x Advanced Security Profiles ---
        CallableCISRule(
            _eval_botnet_detection,
            rule_id="4.1.1",
            title="Ensure Botnet connections are detected",
            level=L2, severity=RuleSeverity.HIGH,
            description="Botnet connection scanning detects compromised endpoints.",
            expected_value="Botnet scanning enabled",
            remediation="Enable botnet connection scanning on interfaces",
            category="Security Profiles", cis_section="4.1.1",
            remediation_cli="config system interface\n  edit <interface>\n    set scan-botnet-connections block\n  next\nend",
        ),
        CallableCISRule(
            _eval_sandbox_inspection,
            rule_id="4.2.6",
            title="Ensure inline scanning with sandbox is enabled",
            level=L2, severity=RuleSeverity.HIGH,
            description="Sandbox analysis detects advanced threats through behavioral analysis.",
            expected_value="Integração com Sandbox configurada",
            remediation="Configure FortiSandbox integration",
            category="Security Profiles", cis_section="4.2.6",
            remediation_cli="config system fortisandbox\n  set status enable\n  set server <sandbox_ip>\nend",
        ),
        CallableCISRule(
            _eval_dns_filter_logging,
            rule_id="4.3.2",
            title="Ensure logging is enabled on DNS Filter",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="DNS filter logging captures DNS-based threat intelligence.",
            expected_value="DNS filter logging enabled",
            remediation="Enable logging on DNS filter profiles",
            category="Security Profiles", cis_section="4.3.2",
            remediation_cli="config dnsfilter profile\n  edit <profile_name>\n    set log-all-domain enable\n  next\nend",
        ),
        CallableCISRule(
            _eval_high_risk_categories,
            rule_id="4.3.4",
            title="Ensure high-risk web categories are blocked",
            level=L2, severity=RuleSeverity.HIGH,
            description="Block access to malicious, phishing, and high-risk web categories.",
            expected_value="High-risk categories blocked",
            remediation="Configure web filter to block high-risk categories",
            category="Security Profiles", cis_section="4.3.4",
            remediation_cli="config webfilter profile\n  edit <profile>\n    config ftgd-wf\n      config filters\n        edit 1\n          set category 26\n          set action block\n        next\n      end\n    end\n  next\nend",
        ),
        CallableCISRule(
            _eval_app_control_logging,
            rule_id="4.4.2",
            title="Ensure logging is enabled on Application Control",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="Application control logging provides visibility into app usage.",
            expected_value="Application control logging enabled",
            remediation="Enable logging on application control profiles",
            category="Security Profiles", cis_section="4.4.2",
            remediation_cli="config application list\n  edit <list_name>\n    set other-application-log enable\n  next\nend",
        ),

        # --- 6.x VPN Configuration ---
        CallableCISRule(
            _eval_vpn_certificate,
            rule_id="6.1.1",
            title="Ensure trusted signed certificate is used for VPN portal",
            level=L2, severity=RuleSeverity.HIGH,
            description="Factory certificates should be replaced with trusted CA-signed certs.",
            expected_value="Custom CA-signed certificate",
            remediation="Replace factory certificate with trusted CA-signed certificate",
            category="VPN", cis_section="6.1.1",
            remediation_cli="config vpn ssl settings\n  set servercert <custom_cert_name>\nend",
        ),
        CallableCISRule(
            _eval_ssl_vpn_tls,
            rule_id="6.1.2",
            title="Ensure limited TLS versions for SSL VPN",
            level=L2, severity=RuleSeverity.HIGH,
            description="SSL VPN should enforce TLS 1.2 or higher.",
            expected_value="TLS 1.2+",
            remediation="Set SSL VPN minimum TLS version to 1.2",
            category="VPN", cis_section="6.1.2",
            remediation_cli="config vpn ssl settings\n  set ssl-min-proto-ver tls1-2\nend",
        ),
        CallableCISRule(
            _eval_vpn_ipsec_encryption,
            rule_id="6.2.1",
            title="Ensure IPsec VPN uses AES-256 encryption",
            level=L2, severity=RuleSeverity.HIGH,
            description="IPsec Phase 1 should use AES-256 or stronger encryption.",
            expected_value="AES-256 encryption",
            remediation="Configure IPsec Phase 1 with AES-256",
            category="VPN", cis_section="6.2.1",
            remediation_cli="config vpn ipsec phase1-interface\n  edit <tunnel>\n    set proposal aes256-sha256\n  next\nend",
        ),
        CallableCISRule(
            _eval_vpn_ipsec_dh_group,
            rule_id="6.2.2",
            title="Ensure IPsec VPN uses strong DH group",
            level=L2, severity=RuleSeverity.HIGH,
            description="Diffie-Hellman group should be 14 or higher for key exchange.",
            expected_value="DH group ≥ 14",
            remediation="Configure IPsec with DH group 14+",
            category="VPN", cis_section="6.2.2",
            remediation_cli="config vpn ipsec phase1-interface\n  edit <tunnel>\n    set dhgrp 14 19 20 21\n  next\nend",
        ),

        # --- 7.x Advanced Logging ---
        CallableCISRule(
            _eval_log_encryption,
            rule_id="7.2.1",
            title="Ensure logs sent to FortiAnalyzer/FortiManager are encrypted",
            level=L2, severity=RuleSeverity.HIGH,
            description="Log transmission should be encrypted to prevent eavesdropping.",
            expected_value="Log encryption enabled",
            remediation="Enable encryption for log transmission",
            category="Logging", cis_section="7.2.1",
            remediation_cli="config log fortianalyzer setting\n  set enc-algorithm high\nend",
        ),

        # --- Additional Advanced Controls ---
        CallableCISRule(
            _eval_ssl_inspection,
            rule_id="4.5.1",
            title="Ensure SSL/SSH inspection is configured",
            level=L2, severity=RuleSeverity.HIGH,
            description="Deep SSL inspection ensures encrypted traffic is inspected for threats.",
            expected_value="SSL/SSH inspection profiles configured",
            remediation="Configure SSL/SSH inspection profiles",
            category="Security Profiles", cis_section="4.5.1",
            remediation_cli="config firewall ssl-ssh-profile\n  edit <profile>\n    config ssl\n      set inspect-all enable\n    end\n  next\nend",
        ),
        CallableCISRule(
            _eval_web_filtering,
            rule_id="4.5.2",
            title="Ensure Web Filtering is enabled",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="Web filtering blocks access to malicious and inappropriate websites.",
            expected_value="Web filtering configured",
            remediation="Configure web filtering profiles",
            category="Security Profiles", cis_section="4.5.2",
            remediation_cli="config webfilter profile\n  edit <profile>\n    set web-content-log enable\n    set web-filter-activex-log enable\n  next\nend",
        ),
        CallableCISRule(
            _eval_email_filter,
            rule_id="4.5.4",
            title="Ensure Email Filtering is configured",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="Email filtering blocks spam, phishing, and malicious attachments.",
            expected_value="Email filtering configured",
            remediation="Configure email filtering profiles",
            category="Security Profiles", cis_section="4.5.4",
        ),
        CallableCISRule(
            _eval_file_filter,
            rule_id="4.5.5",
            title="Ensure File Filtering is configured",
            level=L2, severity=RuleSeverity.MEDIUM,
            description="File filtering blocks dangerous file types from being transferred.",
            expected_value="File filtering configured",
            remediation="Configure file filter profiles",
            category="Security Profiles", cis_section="4.5.5",
        ),
    ]

    return rules
