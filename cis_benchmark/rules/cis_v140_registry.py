import re

from .base import CallableCISRule, CISLevel, RuleSeverity
from . import level1_rules_legacy as legacy_l1
from . import level2_rules_legacy as legacy_l2


# ============================================================
# CIS FORTIGATE 7.0.x v1.4.0
# ============================================================

OFFICIAL_L1 = {
    "1.1",
    "1.2",
    "1.3",

    "2.1.1",
    "2.1.2",
    "2.1.3",
    "2.1.4",
    "2.1.5",
    "2.1.10",
    "2.1.12",

    "2.2.1",
    "2.2.2",

    "2.4.1",
    "2.4.2",
    "2.4.3",
    "2.4.4",
    "2.4.5",
    "2.4.6",
    "2.4.7",
    "2.4.8",

    "2.5.2",
    "2.5.3",

    "3.2",
    "3.3",
    "3.4",

    "4.1.2",

    "4.2.6",

    "4.3.2",
    "4.3.3",

    "4.4.1",
    "4.4.3",
    "4.4.4",

    "5.1.1",

    "7.2.1",
}

OFFICIAL_L2 = {
    "2.1.6",
    "2.1.7",
    "2.1.8",
    "2.1.9",
    "2.1.11",

    "2.3.1",
    "2.3.2",

    "2.5.1",

    "3.1",

    "4.1.1",

    "4.2.1",
    "4.2.2",
    "4.2.3",
    "4.2.4",
    "4.2.5",

    "4.3.1",

    "4.4.2",

    "5.2.1.1",

    "6.1.1",
    "6.1.2",

    "7.1.1",
    "7.3.1",
}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------


def _raw(config):
    """
    Retorna o conteúdo bruto da configuração.

    O FortiGateConfigParser utiliza raw_content.
    """

    value = getattr(config, "raw_content", None)

    if isinstance(value, str):
        return value

    # Compatibilidade com objetos antigos.
    for attr in (
        "raw_config",
        "raw",
        "text",
        "config_text",
    ):
        value = getattr(config, attr, None)

        if isinstance(value, str):
            return value

    return ""



def _blocks(config, name):
    try:
        return config.get_blocks(name) or []
    except Exception:
        return []


def _make(rule, passed, message):
    return rule._make_result(bool(passed), message)


def _policy_text(config):
    raw = _raw(config)
    if raw:
        return raw

    blocks = _blocks(config, "firewall policy")
    return "\n".join(str(x) for x in blocks)


def _policy_blocks(config):
    """
    Retorna cada firewall policy individual.

    O parser da aplicação representa:

        config firewall policy
            edit 1
            edit 2
            ...
        end

    como um ConfigBlock pai contendo os edits em sub_blocks.

    Os controles CIS que avaliam policies precisam receber
    os edits individuais, e não o container pai.
    """

    result = []

    parents = _blocks(config, "firewall policy")

    for parent in parents:
        sub_blocks = getattr(parent, "sub_blocks", []) or []

        if sub_blocks:
            for sub in sub_blocks:
                if getattr(sub, "name", ""):
                    result.append(sub)
        else:
            # Compatibilidade com possíveis estruturas antigas
            # onde a policy já venha diretamente como bloco.
            if (
                getattr(parent, "name", "")
                or getattr(parent, "settings", None)
            ):
                result.append(parent)

    return result


def _cli_values(value):
    """
    Extrai valores de uma linha CLI preservando nomes entre aspas.

    Exemplo:

        set dstintf "wan1" "wan2"

    retorna:

        ["wan1", "wan2"]
    """

    value = str(value or "")

    values = []

    for match in re.finditer(
        r'"([^"]*)"|\'([^\']*)\'|(\S+)',
        value
    ):
        value_found = (
            match.group(1)
            if match.group(1) is not None
            else match.group(2)
            if match.group(2) is not None
            else match.group(3)
        )

        if value_found:
            values.append(value_found)

    return values



def _policy_identifier(block):
    """
    Retorna somente o ID da firewall policy.

    O relatório não exibe o nome da policy para evitar
    relatórios gigantes em FortiGate com centenas ou
    milhares de policies.
    """

    policy_id = (
        str(block.get("policyid", "")).strip()
        or str(block.get("id", "")).strip()
        or str(getattr(block, "name", "")).strip()
    )

    if policy_id.isdigit():
        return policy_id

    return "unknown"



def _format_policy_ids(policy_ids):
    """
    Formata TODOS os IDs das firewall policies.

    Não limita a quantidade e não utiliza '+ more',
    pois o relatório deve permitir que o analista
    identifique e corrija cada policy individualmente.
    """

    ids = [
        str(x).strip()
        for x in policy_ids
        if str(x).strip()
    ]

    total = len(ids)

    if total == 0:
        return "0 políticas"

    return (
        f"{total} políticas (IDs): "
        + ", ".join(ids)
    )



def _allowed_policies(config):
    """
    Retorna somente firewall policies habilitadas que permitem
    tráfego.

    CIS aplica os controles de Security Profiles sobre policies
    que efetivamente permitem tráfego.
    """

    result = []

    for block in _policy_blocks(config):

        status = str(
            block.get("status", "enable")
        ).strip().lower()

        if status in ("disable", "disabled"):
            continue

        action = str(
            block.get("action", "")
        ).strip().lower()

        if action in ("accept", "ipsec"):
            result.append(block)

    return result


def _wan_interface_names(config):
    """
    Descobre interfaces WAN através do próprio config system interface.

    Também reconhece virtual-wan-link, usado pelo FortiOS/SD-WAN.
    """

    names = {
        "virtual-wan-link"
    }

    parents = _blocks(config, "system interface")

    for parent in parents:
        for iface in getattr(parent, "sub_blocks", []) or []:

            name = str(
                getattr(iface, "name", "")
            ).strip().strip('"').strip("'")

            role = str(
                iface.get("role", "")
            ).strip().lower()

            if name and role == "wan":
                names.add(name)

    return {
        str(name).strip().lower()
        for name in names
        if str(name).strip()
    }


def _internet_policies(config):
    """
    Retorna policies permitidas e habilitadas cujo destino aponta
    para uma interface WAN detectável.

    Isso evita aplicar 4.3.3 indiscriminadamente em policies
    internas/VPN.

    Compatível com:
      - interfaces com role wan
      - virtual-wan-link
    """

    wan_names = _wan_interface_names(config)

    result = []

    for block in _allowed_policies(config):

        dst_interfaces = _cli_values(
            block.get("dstintf", "")
        )

        if any(
            interface.strip().lower() in wan_names
            for interface in dst_interfaces
        ):
            result.append(block)

    return result


# ============================================================
# NOVOS CONTROLES OFICIAIS
# ============================================================


# ============================================================
# NOVOS CONTROLES OFICIAIS
# ============================================================


def _cis_raw_content(config):
    """
    Retorna o conteúdo bruto real do FortiGateConfig.

    O parser oficial desta aplicação utiliza:
        FortiGateConfig.raw_content
    """
    value = getattr(config, "raw_content", "")
    return value if isinstance(value, str) else ""


def _cis_unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _cis_parse_top_level_edits(raw, config_name):
    """
    Extrai os blocos edit diretamente dentro de:
        config <config_name>

    O parser trabalha com sintaxe FortiGate indentada.
    """
    import re

    lines = raw.splitlines()
    start = None

    wanted = config_name.lower()

    for i, line in enumerate(lines):
        if line.strip().lower() == f"config {wanted}":
            start = i
            break

    if start is None:
        return []

    result = []
    current = None
    depth = 0

    for line in lines[start + 1:]:
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.lower() == "end":
            if depth == 0:
                break
            depth -= 1
            continue

        if re.match(r"^config\s+", stripped, re.I):
            depth += 1
            continue

        if re.match(r"^end$", stripped, re.I):
            continue

        # edit de primeiro nível:
        #     edit "nome"
        if depth == 0:
            m = re.match(r'^\s{4}edit\s+"?([^"]+)"?\s*$', line, re.I)
            if m:
                if current is not None:
                    result.append(current)

                current = {
                    "name": m.group(1).strip(),
                    "lines": [],
                }
                continue

            if current is not None:
                # next do primeiro nível
                if re.match(r"^\s{4}next\s*$", line, re.I):
                    result.append(current)
                    current = None
                    continue

                current["lines"].append(line)

    if current is not None:
        result.append(current)

    return result


def _cis_application_profiles(raw):
    """
    Retorna todos os Application Control Profiles definidos em:
        config application list

    Cada item:
        {
          name,
          lines
        }
    """
    return _cis_parse_top_level_edits(raw, "application list")


def _cis_application_categories(profile_lines):
    """
    Analisa as entradas do Application Control Profile.

    CIS 4.4.1:
      categoria 2 = P2P
      categoria 6 = Proxy

    Consideramos a categoria bloqueada quando a entrada contém:
        set category 2 ...
        set action block

    ou:
        set category 2 6
        set action block

    A análise é feita por entrada, preservando a associação
    categoria -> ação.
    """
    import re

    entries = []

    lines = profile_lines
    current = None
    depth = 0

    for line in lines:
        stripped = line.strip()

        if re.match(r"^config\s+", stripped, re.I):
            depth += 1
            continue

        if stripped.lower() == "end":
            if depth > 0:
                depth -= 1
            continue

        if depth <= 0:
            continue

        # entradas dentro de config entries
        m = re.match(r'^\s{8}edit\s+"?([^"]+)"?\s*$', line, re.I)
        if m:
            if current is not None:
                entries.append(current)

            current = {
                "name": m.group(1).strip(),
                "categories": [],
                "action": "",
                "lines": [],
            }
            continue

        if current is None:
            continue

        if re.match(r"^\s{8}next\s*$", line, re.I):
            entries.append(current)
            current = None
            continue

        current["lines"].append(line)

        cm = re.match(r"^\s*set\s+category\s+(.+)$", stripped, re.I)
        if cm:
            nums = re.findall(r"\b\d+\b", cm.group(1))
            current["categories"] = [int(x) for x in nums]

        am = re.match(r"^\s*set\s+action\s+(\S+)", stripped, re.I)
        if am:
            current["action"] = am.group(1).strip('"').lower()

    if current is not None:
        entries.append(current)

    p2p = False
    proxy = False
    p2p_evidence = []
    proxy_evidence = []

    for entry in entries:
        cats = set(entry["categories"])
        action = entry["action"]

        if 2 in cats:
            evidence = (
                f'entrada {entry["name"]}: categoria 2 -> action {action or "ausente"}'
            )
            p2p_evidence.append(evidence)

            if action == "block":
                p2p = True

        if 6 in cats:
            evidence = (
                f'entrada {entry["name"]}: categoria 6 -> action {action or "ausente"}'
            )
            proxy_evidence.append(evidence)

            if action == "block":
                proxy = True

    return {
        "p2p": p2p,
        "proxy": proxy,
        "p2p_evidence": p2p_evidence,
        "proxy_evidence": proxy_evidence,
    }


def _cis_policy_application_profiles(raw):
    """
    Mapeia:
        Application Control Profile -> firewall policies

    Somente policies habilitadas entram na decisão.

    Sintaxe esperada:
        config firewall policy
            edit 10
                set status enable
                set application-list "perfil"
            next
    """
    import re

    policies = _cis_parse_top_level_edits(raw, "firewall policy")
    mapping = {}

    for policy in policies:
        name = policy["name"]
        lines = policy["lines"]

        status = "enable"
        profile = None

        for line in lines:
            stripped = line.strip()

            sm = re.match(r'^set\s+status\s+(\S+)', stripped, re.I)
            if sm:
                status = sm.group(1).strip('"').lower()

            am = re.match(
                r'^set\s+application-list\s+"([^"]+)"',
                stripped,
                re.I
            )
            if not am:
                am = re.match(
                    r'^set\s+application-list\s+(\S+)',
                    stripped,
                    re.I
                )

            if am:
                profile = am.group(1).strip('"')

        if status == "disable":
            continue

        if profile:
            mapping.setdefault(profile, []).append(name)

    return mapping


def _eval_cpu_overload(rule, config):
    """
    CIS 2.1.12

    Ensure single CPU core overloaded event is logged.

    Verifica:

        set log-single-cpu-high enable
    """

    raw = _raw(config)

    if not raw:
        return _make(
            rule,
            False,
            "Não foi possível acessar o conteúdo bruto da configuração"
        )

    match = re.search(
        r"(?im)^\s*set\s+log-single-cpu-high\s+(\S+)\s*$",
        raw
    )

    if not match:
        return _make(
            rule,
            False,
            "log-single-cpu-high não está configurado como enable"
        )

    value = (
        match.group(1)
        .strip()
        .strip('"')
        .lower()
    )

    if value == "enable":
        return _make(
            rule,
            True,
            "PASS: log-single-cpu-high está configurado como enable"
        )

    return _make(
        rule,
        False,
        f"FAIL: log-single-cpu-high está configurado como {value}"
    )



def _eval_default_admin_password(rule, config):
    """
    CIS 7.0.x v1.4.0 - 2.4.1

    O backup exportado do FortiGate não expõe a senha em texto claro.
    Quando o usuário admin possui uma credencial ENC configurada,
    o auditor pode confirmar que existe uma senha configurada.

    A comparação criptográfica com a senha padrão não é possível
    somente a partir do arquivo de configuração exportado.
    """
    raw = _raw(config)

    admin_match = re.search(
        r'(?ims)^\\s*edit\\s+["\']?admin["\']?\\s*$'
        r'(?P<body>.*?)(?=^\\s*edit\\s+|^\\s*end\\s*$)',
        raw,
    )

    if not admin_match:
        return _make(
            rule,
            True,
            "Conta local padrão 'admin' não encontrada no arquivo de configuração"
        )

    body = admin_match.group("body")

    password = re.search(
        r'^\\s*set\\s+password\\s+(?P<value>.+?)\\s*$',
        body,
        re.I | re.M,
    )

    if password:
        value = password.group("value").strip()

        if value and value.lower() not in ("none", '""', "''"):
            if value.upper().startswith("ENC "):
                return _make(
                    rule,
                    True,
                    "Conta padrão 'admin' possui credencial configurada (ENC); "
                    "a senha em texto claro não é exposta pelo backup"
                )

            return _make(
                rule,
                True,
                "Conta padrão 'admin' possui senha configurada"
            )

    return _make(
        rule,
        False,
        "Conta padrão 'admin' não possui senha configurada no arquivo"
    )


def _eval_admin_trusted_hosts(rule, config):
    blocks = _blocks(config, "system admin")

    if not blocks:
        return _make(rule, False, "No system admin configuration found")

    missing = []

    for block in blocks:
        name = str(
            block.get("name")
            or block.get("edit")
            or block.get("id")
            or ""
        ).strip("'\"")

        if not name:
            continue

        trusted = any(
            str(k).lower().startswith("trusthost")
            and str(v).strip() not in ("", "0.0.0.0", "0.0.0.0/0")
            for k, v in block.items()
        )

        if not trusted:
            missing.append(name)

    if not missing:
        return _make(
            rule,
            True,
            "All detected administrator accounts have specific trusted hosts"
        )

    return _make(
        rule,
        False,
        "Administrator accounts without specific trusted hosts: "
        + ", ".join(missing)
    )



def _eval_admin_profiles(rule, config):
    """
    CIS 2.4.3

    Ensure administrator accounts have correct profiles assigned.

    O resultado não expõe:
      - nome dos administradores
      - username
      - accprofile individual
      - dados de login

    O relatório informa somente PASS/FAIL.
    """

    raw = _raw(config)

    if not raw:
        return _make(
            rule,
            False,
            "FAIL: não foi possível analisar as contas administrativas"
        )

    # --------------------------------------------------------
    # Localizar config system admin
    # --------------------------------------------------------

    lines = raw.splitlines()

    start = None

    for i, line in enumerate(lines):
        if re.match(
            r"^\s*config\s+system\s+admin\s*$",
            line,
            re.I
        ):
            start = i
            break

    if start is None:
        return _make(
            rule,
            False,
            "FAIL: configuração de administradores não encontrada"
        )

    # --------------------------------------------------------
    # Capturar o bloco system admin
    # --------------------------------------------------------

    block_lines = []

    base_indent = None

    for i in range(start + 1, len(lines)):

        line = lines[i]

        stripped = line.strip()

        if stripped.lower() == "end":
            # Primeiro end no mesmo nível encerra
            # config system admin.
            indent = len(line) - len(line.lstrip())

            if base_indent is None:
                base_indent = len(lines[start]) - len(lines[start].lstrip())

            if indent <= base_indent:
                break

        block_lines.append(line)

    # --------------------------------------------------------
    # Encontrar cada edit de administrador
    # --------------------------------------------------------

    admins = []

    current = None
    current_indent = None

    for line in block_lines:

        stripped = line.strip()

        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())

        # Admins são edit no primeiro nível dentro do bloco.
        edit_match = re.match(
            r'^edit\s+"?([^"]+)"?\s*$',
            stripped,
            re.I
        )

        if edit_match:
            if current is not None:
                admins.append(current)

            current = {
                "has_accprofile": False
            }

            current_indent = indent
            continue

        if current is None:
            continue

        # Só considera set accprofile dentro do admin atual.
        if indent <= current_indent:
            continue

        acc_match = re.match(
            r'^set\s+accprofile\s+"?([^"\s]+)"?\s*$',
            stripped,
            re.I
        )

        if acc_match:
            value = acc_match.group(1).strip()

            if value:
                current["has_accprofile"] = True

    if current is not None:
        admins.append(current)

    # --------------------------------------------------------
    # Se o parser não encontrou os edits, fallback simples
    # usando o conteúdo do bloco.
    # --------------------------------------------------------

    if not admins:

        admin_text = "\n".join(block_lines)

        edit_count = len(
            re.findall(
                r'(?m)^\s*edit\s+"?[^"\n]+"?\s*$',
                admin_text,
                re.I
            )
        )

        acc_count = len(
            re.findall(
                r'(?m)^\s*set\s+accprofile\s+"?[^"\s]+"?\s*$',
                admin_text,
                re.I
            )
        )

        if edit_count == 0:
            return _make(
                rule,
                False,
                "FAIL: não foi possível identificar contas administrativas"
            )

        if acc_count >= edit_count:
            return _make(
                rule,
                True,
                "PASS: todas as contas administrativas possuem accprofile configurado"
            )

        return _make(
            rule,
            False,
            "FAIL: existem contas administrativas sem accprofile configurado"
        )

    # --------------------------------------------------------
    # Decisão
    # --------------------------------------------------------

    if all(
        admin["has_accprofile"]
        for admin in admins
    ):
        return _make(
            rule,
            True,
            "PASS: todas as contas administrativas possuem accprofile configurado"
        )

    return _make(
        rule,
        False,
        "FAIL: existem contas administrativas sem accprofile configurado"
    )



def _eval_local_in_virtual_patch(rule, config):
    blocks = _blocks(config, "firewall local-in-policy")

    for block in blocks:
        value = str(block.get("virtual-patch", "")).lower()

        if value == "enable":
            return _make(
                rule,
                True,
                "Virtual patching enabled on local-in policy"
            )

    raw = _raw(config)

    if re.search(
        r"config\s+firewall\s+local-in-policy.*?"
        r"set\s+virtual-patch\s+enable",
        raw,
        re.I | re.S,
    ):
        return _make(
            rule,
            True,
            "Virtual patching enabled on local-in policy"
        )

    return _make(
        rule,
        False,
        "No local-in policy with virtual patching enabled"
    )


def _eval_ha_monitor(rule, config):
    raw = _raw(config).lower()

    if not re.search(r"config\s+system\s+ha\b", raw):
        return _make(
            rule,
            False,
            "HA is not configured"
        )

    try:
        result = legacy_l1._eval_ha_monitor_interfaces(rule, config)
        return result
    except Exception:
        pass

    if re.search(r"set\s+monitor\s+\S+", raw):
        return _make(
            rule,
            True,
            "HA monitor interface configuration detected"
        )

    return _make(
        rule,
        False,
        "HA is configured but no monitor interface was detected"
    )


def _eval_ha_reserved(rule, config):
    raw = _raw(config).lower()

    if not re.search(r"config\s+system\s+ha\b", raw):
        return _make(
            rule,
            True,
            "Not applicable: FortiGate is not configured as an HA cluster"
        )

    if re.search(
        r"set\s+ha-mgmt-status\s+enable",
        raw,
        re.I,
    ):
        return _make(
            rule,
            True,
            "HA reserved management interface enabled"
        )

    return _make(
        rule,
        False,
        "HA is configured but reserved management interface is not enabled"
    )


def _eval_snmp_trusted_hosts(rule, config):
    raw = _raw(config)

    if not re.search(r"config\s+system\s+snmp\b", raw, re.I):
        return _make(
            rule,
            True,
            "SNMP agent is not configured; trusted-host requirement is not applicable"
        )

    if re.search(r"trusthost\d+\s+\S+", raw, re.I):
        return _make(
            rule,
            True,
            "SNMP trusted hosts detected"
        )

    return _make(
        rule,
        False,
        "SNMP is configured but no specific trusted host was detected"
    )


def _eval_ha_config(rule, config):
    raw = _raw(config)

    if re.search(r"config\s+system\s+ha\b", raw, re.I):
        return _make(
            rule,
            True,
            "HA configuration detected"
        )

    return _make(
        rule,
        False,
        "HA configuration not detected"
    )


def _eval_unused_policies(rule, config):
    blocks = _policy_blocks(config)

    if not blocks:
        return _make(
            rule,
            True,
            "Nenhuma política de firewall encontrada para revisão"
        )

    # This control is a review/process control. A static exported
    # configuration cannot reliably prove historical review.
    return _make(
        rule,
        True,
        f"{len(blocks)} políticas de firewall encontradas; revisão da configuração necessária"
    )


def _eval_av_profile(rule, config):
    policies = _allowed_policies(config)

    if not policies:
        return _make(
            rule,
            True,
            "Nenhuma política de firewall permitida encontrada"
        )

    missing = []

    for block in policies:
        av = str(
            block.get("av-profile")
            or block.get("av-profile-override")
            or ""
        ).strip()

        if not av:
            missing.append(_policy_identifier(block))

    if not missing:
        return _make(
            rule,
            True,
            "Antivirus security profile applied to allowed policies"
        )

    return _make(
        rule,
        False,
        "Políticas permitidas sem perfil Antivirus: "
        + _format_policy_ids(missing)
    )


def _eval_dns_filter_profile(rule, config):
    policies = _internet_policies(config)

    if not policies:
        return _make(
            rule,
            True,
            "No enabled allowed firewall policies with a detectable WAN destination"
        )

    missing = []

    for block in policies:

        dns = str(
            block.get("dnsfilter-profile", "")
        ).strip()

        if not dns:
            pid = (
                str(block.get("policyid", "")).strip()
                or str(block.get("id", "")).strip()
                or str(getattr(block, "name", "")).strip()
                or "unknown"
            )

            missing.append(pid)

    if not missing:
        return _make(
            rule,
            True,
            "DNS Filter security profile applied to all detected outbound Internet policies"
        )

    return _make(
        rule,
        False,
        "Políticas de Internet de saída sem perfil DNS Filter: "
        + _format_policy_ids(missing)
    )


def _eval_high_risk_applications(rule, config):
    """
    CIS 4.4.1

    Block high risk categories on Application Control.

    CIS:
      Category 2 = P2P
      Category 6 = Proxy

    A avaliação é feita diretamente sobre raw_content.

    Somente Application Control Profiles efetivamente
    utilizados por firewall policies habilitadas são avaliados.

    O profile precisa conter uma entrada com:
        set category ... 2 ...
        set action block

    e uma entrada com:
        set category ... 6 ...
        set action block
    """

    raw = getattr(config, "raw_content", "")

    if not isinstance(raw, str) or not raw.strip():
        return rule._make_result(
            False,
            "FAIL: conteúdo bruto da configuração não disponível"
        )

    lines = raw.splitlines()

    # ========================================================
    # 1. LOCALIZAR FIREWALL POLICIES
    # ========================================================

    fw_start = None

    for i, line in enumerate(lines):

        if line.strip().lower() == "config firewall policy":
            fw_start = i
            break

    if fw_start is None:
        return rule._make_result(
            False,
            "FAIL: config firewall policy não encontrada"
        )

    fw_lines = []

    for line in lines[fw_start + 1:]:

        stripped = line.strip()

        if stripped.lower() == "end":
            break

        fw_lines.append(line)

    # ========================================================
    # 2. EXTRAIR APPLICATION-LIST DAS POLICIES HABILITADAS
    # ========================================================

    used_profiles = set()

    current_policy = None
    policy_lines = []

    def process_policy():
        if current_policy is None:
            return

        block = "\n".join(policy_lines)

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
            return

        app_match = re.search(
            r'^\s*set\s+application-list\s+(.+)$',
            block,
            re.I | re.M
        )

        if not app_match:
            return

        value = app_match.group(1).strip()

        # ----------------------------------------------------
        # CRÍTICO:
        # Ignorar application-list vazio.
        #
        # set application-list ''
        # set application-list ""
        # ----------------------------------------------------

        if value in ("''", '""'):
            return

        # Pode haver aspas.
        value = value.strip('"').strip("'").strip()

        if not value:
            return

        used_profiles.add(value)

    for line in fw_lines:

        stripped = line.strip()

        m = re.match(
            r'^edit\s+(.+)$',
            stripped,
            re.I
        )

        if m:

            if current_policy is not None:
                process_policy()

            current_policy = m.group(1).strip().strip('"')
            policy_lines = []

            continue

        if stripped.lower() == "next":

            process_policy()

            current_policy = None
            policy_lines = []

            continue

        if current_policy is not None:
            policy_lines.append(line)

    process_policy()

    # ========================================================
    # 3. VALIDAR SE EXISTEM PROFILES UTILIZADOS
    # ========================================================

    if not used_profiles:

        return rule._make_result(
            False,
            "FAIL: nenhuma Application Control Profile "
            "não vazia utilizada por policy habilitada foi encontrada"
        )

    # ========================================================
    # 4. LOCALIZAR CONFIG APPLICATION LIST
    # ========================================================

    app_start = None

    for i, line in enumerate(lines):

        if line.strip().lower() == "config application list":
            app_start = i
            break

    if app_start is None:

        return rule._make_result(
            False,
            "FAIL: config application list não encontrada"
        )

    app_lines = []

    # --------------------------------------------------------
    # IMPORTANTE:
    # "config application list" possui blocos "config" internos,
    # principalmente "config entries".
    #
    # Não podemos parar no primeiro "end", pois esse "end"
    # pode pertencer a um bloco interno.
    #
    # Aqui controlamos a profundidade dos blocos "config/end"
    # e somente encerramos quando chegamos ao "end" correspondente
    # ao próprio "config application list".
    # --------------------------------------------------------

    config_depth = 1

    for line in lines[app_start + 1:]:

        stripped = line.strip().lower()

        if stripped.startswith("config "):
            config_depth += 1
            app_lines.append(line)
            continue

        if stripped == "end":
            config_depth -= 1

            if config_depth == 0:
                break

            app_lines.append(line)
            continue

        app_lines.append(line)

    # ========================================================
    # 5. INDEXAR OS PROFILES
    # ========================================================

    profiles = {}

    current_profile = None
    profile_lines = []

    def save_profile():

        nonlocal current_profile
        nonlocal profile_lines

        if current_profile is None:
            return

        profiles[current_profile] = "\n".join(profile_lines)

    for line in app_lines:

        # Profile sempre é edit com 4 espaços.
        m = re.match(
            r'^\s{4}edit\s+"([^"]+)"\s*$',
            line,
            re.I
        )

        if m:

            if current_profile is not None:
                save_profile()

            current_profile = m.group(1)
            profile_lines = []

            continue

        # Também aceita edit sem aspas.
        m = re.match(
            r'^\s{4}edit\s+(\S+)\s*$',
            line,
            re.I
        )

        if m:

            if current_profile is not None:
                save_profile()

            current_profile = m.group(1).strip('"').strip("'")
            profile_lines = []

            continue

        if current_profile is not None:
            profile_lines.append(line)

    if current_profile is not None:
        save_profile()

    # ========================================================
    # 6. AVALIAR PROFILES USADOS
    # ========================================================

    missing = []
    invalid = []
    valid = []

    for profile_name in sorted(used_profiles):

        if profile_name not in profiles:

            missing.append(profile_name)
            continue

        profile = profiles[profile_name]

        category_2_blocked = False
        category_6_blocked = False

        # ----------------------------------------------------
        # Cada "edit N" dentro de config entries representa
        # uma regra de Application Control.
        # ----------------------------------------------------

        entry_matches = list(
            re.finditer(
                r'(?m)^\s{12}edit\s+(\d+)\s*$',
                profile
            )
        )

        for index, entry_match in enumerate(entry_matches):

            start = entry_match.start()

            if index + 1 < len(entry_matches):
                end = entry_matches[index + 1].start()
            else:
                end = len(profile)

            entry = profile[start:end]

            category_match = re.search(
                r'^\s*set\s+category\s+(.+)$',
                entry,
                re.I | re.M
            )

            action_match = re.search(
                r'^\s*set\s+action\s+(\S+)',
                entry,
                re.I | re.M
            )

            if not category_match or not action_match:
                continue

            categories = set(
                re.findall(
                    r'\b\d+\b',
                    category_match.group(1)
                )
            )

            action = (
                action_match.group(1)
                .strip()
                .lower()
            )

            if action != "block":
                continue

            if "2" in categories:
                category_2_blocked = True

            if "6" in categories:
                category_6_blocked = True

        if category_2_blocked and category_6_blocked:

            valid.append(profile_name)

        else:

            missing_categories = []

            if not category_2_blocked:
                missing_categories.append("P2P(2)")

            if not category_6_blocked:
                missing_categories.append("Proxy(6)")

            invalid.append(
                f"{profile_name}: " +
                ", ".join(missing_categories)
            )

    # ========================================================
    # 7. RESULTADO
    # ========================================================

    if missing:

        return rule._make_result(
            False,
            "FAIL: Application Control Profile utilizado "
            "por policy não encontrado: " +
            ", ".join(missing)
        )

    if invalid:

        return rule._make_result(
            False,
            "FAIL: Application Control sem bloqueio das "
            "categorias exigidas pelo CIS: " +
            "; ".join(invalid)
        )

    return rule._make_result(
        True,
        "PASS: todos os Application Control Profiles "
        "utilizados por policies habilitadas bloqueiam "
        "P2P (categoria 2) e Proxy (categoria 6): " +
        ", ".join(valid)
    )

def _eval_app_control_profile(rule, config):
    policies = _allowed_policies(config)

    if not policies:
        return _make(
            rule,
            True,
            "Nenhuma política de firewall permitida encontrada"
        )

    missing = []

    for block in policies:
        profile = str(
            block.get("application-list")
            or block.get("application-control-profile")
            or ""
        ).strip()

        if not profile:
            missing.append(_policy_identifier(block))

    if not missing:
        return _make(
            rule,
            True,
            "Application Control security profile applied to allowed policies"
        )

    return _make(
        rule,
        False,
        "Políticas permitidas sem perfil Application Control: "
        + _format_policy_ids(missing)
    )


# ============================================================
# RULE CONSTRUCTORS
# ============================================================

def _rule(
    evaluator,
    rule_id,
    title,
    level,
    severity=RuleSeverity.MEDIUM,
    description="",
    expected="Configured",
    remediation="Review and configure according to the CIS benchmark.",
):
    return CallableCISRule(
        evaluator,
        rule_id=rule_id,
        title=title,
        level=level,
        severity=severity,
        description=description,
        expected_value=expected,
        remediation=remediation,
        category="CIS FortiGate 7.0.x",
        cis_section=rule_id,
    )


NEW_L1 = [
    _rule(
        _eval_cpu_overload,
        "2.1.12",
        "Ensure single CPU core overloaded event is logged",
        CISLevel.LEVEL_1,
        expected="log-single-cpu-high: enable",
    ),
    _rule(
        _eval_default_admin_password,
        "2.4.1",
        "Ensure default 'admin' password is changed",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_admin_trusted_hosts,
        "2.4.2",
        "Ensure all login accounts have specific trusted hosts enabled",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_admin_profiles,
        "2.4.3",
        "Ensure administrator accounts have correct profiles assigned",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_local_in_virtual_patch,
        "2.4.8",
        "Virtual patching on the local-in management interface",
        CISLevel.LEVEL_1,
        expected="At least one local-in policy with virtual patching enabled",
    ),
    _rule(
        _eval_ha_monitor,
        "2.5.2",
        "Ensure HA monitor interfaces are configured",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_ha_reserved,
        "2.5.3",
        "Ensure HA Reserved Management Interface is Configured",
        CISLevel.LEVEL_1,
        expected="HA reserved management interface enabled",
    ),
    _rule(
        _eval_dns_filter_profile,
        "4.3.3",
        "Apply DNS Filter Security Profile to Policies",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_high_risk_applications,
        "4.4.1",
        "Block high risk categories on Application Control",
        CISLevel.LEVEL_1,
    ),
    _rule(
        _eval_app_control_profile,
        "4.4.4",
        "Apply Application Control Security Profile to Policies",
        CISLevel.LEVEL_1,
    ),
]


NEW_L2 = [
    _rule(
        _eval_snmp_trusted_hosts,
        "2.3.2",
        "Ensure SNMPv3 trusted hosts are configured",
        CISLevel.LEVEL_2,
    ),
    _rule(
        _eval_ha_config,
        "2.5.1",
        "Ensure HA configuration is configured",
        CISLevel.LEVEL_2,
    ),
    _rule(
        _eval_unused_policies,
        "3.1",
        "Ensure that unused policies are reviewed regularly",
        CISLevel.LEVEL_2,
    ),
    _rule(
        _eval_av_profile,
        "4.2.2",
        "Apply Antivirus Security Profile to Policies",
        CISLevel.LEVEL_2,
    ),
]


# ============================================================
# LEGACY RULE COLLECTION
# ============================================================

def _collect_legacy():
    result = []

    try:
        result.extend(legacy_l1.get_level1_rules())
    except Exception:
        try:
            result.extend(legacy_l1.get_all_rules())
        except Exception:
            pass

    try:
        result.extend(legacy_l2.get_level2_rules())
    except Exception:
        try:
            result.extend(legacy_l2.get_all_rules())
        except Exception:
            pass

    return result


def _index_legacy():
    result = {}

    for rule in _collect_legacy():
        rid = str(getattr(rule, "rule_id", "")).strip()

        if rid:
            result[rid] = rule

    return result


def _normalize_level(rule, level):
    try:
        rule.level = level
    except Exception:
        pass

    return rule


def get_all_rules():
    legacy = _index_legacy()

    result = {}

    # Only official IDs are allowed.
    for rid in OFFICIAL_L1 | OFFICIAL_L2:
        if rid in legacy:
            result[rid] = legacy[rid]

    # Correct official level assignments.
    for rid in OFFICIAL_L1:
        if rid in result:
            _normalize_level(result[rid], CISLevel.LEVEL_1)

    for rid in OFFICIAL_L2:
        if rid in result:
            _normalize_level(result[rid], CISLevel.LEVEL_2)

    # Add missing official controls.
    for rule in NEW_L1:
        result[rule.rule_id] = rule

    for rule in NEW_L2:
        result[rule.rule_id] = rule

    return sorted(
        result.values(),
        key=lambda r: tuple(
            int(x) if x.isdigit() else x
            for x in str(r.rule_id).split(".")
        ),
    )


def get_level1_rules():
    return [
        r for r in get_all_rules()
        if getattr(r, "level", None) == CISLevel.LEVEL_1
    ]


def get_level2_rules():
    return [
        r for r in get_all_rules()
        if getattr(r, "level", None) == CISLevel.LEVEL_2
    ]
