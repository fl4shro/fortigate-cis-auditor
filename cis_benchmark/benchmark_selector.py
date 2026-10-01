from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkSelection:
    supported: bool
    fortios_version: str
    benchmark: str
    message: str


def detect_fortios_version(raw_config: str) -> str:
    """
    Detecta a versão do FortiOS a partir do cabeçalho do backup/config.

    Exemplos aceitos:
      FortiOS v7.0.19
      FortiOS 7.0.19
      Version: FortiGate-200F v7.0.19
      version 7.4.8
    """

    patterns = [
        r"FortiOS[\s\-]*v?(\d+\.\d+\.\d+)",
        r"FortiGate[^\n]*v(\d+\.\d+\.\d+)",
        r"\bversion[\s:=]+v?(\d+\.\d+\.\d+)",
        r"\bv(\d+\.\d+\.\d+)\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, raw_config, re.IGNORECASE)
        if match:
            return match.group(1)

    return ""


def select_benchmark(raw_config: str) -> BenchmarkSelection:
    version = detect_fortios_version(raw_config)

    if not version:
        return BenchmarkSelection(
            supported=False,
            fortios_version="unknown",
            benchmark="unknown",
            message=(
                "Não foi possível identificar a versão do FortiOS. "
                "A auditoria CIS não será executada para evitar aplicar "
                "um benchmark incompatível."
            ),
        )

    major_minor = ".".join(version.split(".")[:2])

    if major_minor == "7.0":
        return BenchmarkSelection(
            supported=True,
            fortios_version=version,
            benchmark="CIS FortiGate 7.0.x v1.4.0",
            message=(
                f"FortiOS {version} detectado. "
                "Aplicando CIS FortiGate 7.0.x v1.4.0."
            ),
        )

    if major_minor == "7.4":
        return BenchmarkSelection(
            supported=False,
            fortios_version=version,
            benchmark="CIS FortiGate 7.4.x v1.0.1",
            message=(
                f"FortiOS {version} detectado. "
                "O CIS FortiGate 7.4.x v1.0.1 existe oficialmente, "
                "mas este engine local não possui os artefatos oficiais "
                "do CIS-CAT necessários para executar esse benchmark. "
                "O benchmark 7.0.x NÃO será aplicado."
            ),
        )

    if major_minor == "7.6":
        return BenchmarkSelection(
            supported=False,
            fortios_version=version,
            benchmark="Nenhum benchmark CIS FortiGate 7.6.x oficial listado",
            message=(
                f"FortiOS {version} detectado. "
                "Não há benchmark CIS FortiGate 7.6.x oficial listado "
                "atualmente. A auditoria CIS não será executada."
            ),
        )

    return BenchmarkSelection(
        supported=False,
        fortios_version=version,
        benchmark="unsupported",
        message=(
            f"FortiOS {version} detectado. "
            "Esta versão não possui motor CIS configurado neste auditor."
        ),
    )
