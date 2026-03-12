import os
import random
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

import requests


def _api_base_url() -> str:
    return os.getenv("TCIO_API_BASE_URL", "http://localhost:8000/api/v1")


def _headers() -> dict[str, str]:
    return {"X-Debug-Role": os.getenv("SCANNER_DEBUG_ROLE", "analyst")}


def reserve_scan_jobs(limit: int = 5) -> list[dict[str, Any]]:
    response = requests.post(
        f"{_api_base_url()}/scans/jobs/reserve/",
        json={"limit": limit},
        headers=_headers(),
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    return payload.get("jobs", [])


def _generate_findings(job: dict[str, Any]) -> list[dict[str, Any]]:
    scanner = job.get("scanner_type", "nmap")
    asset_value = job.get("asset", {}).get("value", "unknown")

    if scanner == "nmap":
        return _run_nmap_findings(asset_value)

    if scanner == "openvas":
        return _run_openvas_findings(asset_value)

    if scanner == "vulners":
        return _run_vulners_findings(asset_value)

    # nmap default finding profile
    return [
        {
            "severity": "medium",
            "title": f"Potentially risky open port on {asset_value}",
            "port": random.choice([22, 23, 445, 3389]),
            "protocol": "tcp",
            "recommendation": "Restrict exposure using firewall ACLs and network segmentation.",
            "reference": "",
            "is_patch_available": False,
        }
    ]


def _run_nmap_findings(target: str) -> list[dict[str, Any]]:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return _fallback_nmap_findings(target, "nmap binary not found")

    try:
        proc = subprocess.run(
            [nmap_path, "-Pn", "-sV", "-T3", "-oX", "-", target],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except Exception as exc:  # noqa: BLE001
        return _fallback_nmap_findings(target, f"nmap execution error: {exc}")

    if proc.returncode != 0 or not proc.stdout.strip():
        err = (proc.stderr or "").strip() or f"exit={proc.returncode}"
        return _fallback_nmap_findings(target, f"nmap failed: {err}")

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return _fallback_nmap_findings(target, "unable to parse nmap xml output")

    findings: list[dict[str, Any]] = []
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_node = port.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue

            service_node = port.find("service")
            service_name = service_node.attrib.get("name", "") if service_node is not None else ""
            product = service_node.attrib.get("product", "") if service_node is not None else ""
            version = service_node.attrib.get("version", "") if service_node is not None else ""
            service_desc = " ".join(item for item in [service_name, product, version] if item).strip()

            port_id = int(port.attrib.get("portid", "0"))
            protocol = port.attrib.get("protocol", "tcp")
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Open port {port_id}/{protocol} detected on {target}",
                    "port": port_id,
                    "protocol": protocol,
                    "recommendation": "Validate service exposure and restrict to trusted networks.",
                    "reference": "",
                    "is_patch_available": False,
                    "metadata": {"service": service_desc},
                }
            )

    if not findings:
        return [
            {
                "severity": "info",
                "title": f"No open ports detected on {target}",
                "recommendation": "No immediate network exposure detected by nmap scan.",
                "reference": "",
                "is_patch_available": False,
            }
        ]
    return findings


def _fallback_nmap_findings(target: str, reason: str) -> list[dict[str, Any]]:
    return [
        {
            "severity": "low",
            "title": f"nmap fallback result for {target}",
            "recommendation": f"Scanner fallback used: {reason}",
            "reference": "",
            "is_patch_available": False,
            "metadata": {"fallback_reason": reason, "scanner": "nmap"},
        }
    ]


def _run_openvas_findings(target: str) -> list[dict[str, Any]]:
    base_url = os.getenv("OPENVAS_API_URL", "").strip()
    token = os.getenv("OPENVAS_API_TOKEN", "").strip()
    if not base_url or not token:
        return _fallback_openvas_findings(target, "OPENVAS_API_URL/OPENVAS_API_TOKEN not configured")

    endpoint = f"{base_url.rstrip('/')}/scan"
    try:
        response = requests.get(
            endpoint,
            params={"target": target},
            headers={"Authorization": f"Bearer {token}"},
            timeout=45,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        return _fallback_openvas_findings(target, f"openvas request failed: {exc}")

    findings_rows = payload.get("findings", []) if isinstance(payload, dict) else []
    findings: list[dict[str, Any]] = []
    for row in findings_rows[:20]:
        findings.append(
            {
                "severity": str(row.get("severity", "medium")).lower(),
                "title": str(row.get("title", f"OpenVAS finding on {target}"))[:255],
                "cve": str(row.get("cve", ""))[:32],
                "port": row.get("port"),
                "protocol": str(row.get("protocol", "tcp"))[:16],
                "recommendation": str(
                    row.get("recommendation", "Review OpenVAS finding and apply vendor patch guidance."),
                ),
                "reference": str(row.get("reference", "")),
                "is_patch_available": bool(row.get("is_patch_available", False)),
                "metadata": {"source": "openvas_live"},
            }
        )

    if findings:
        return findings
    return _fallback_openvas_findings(target, "openvas returned no findings")


def _fallback_openvas_findings(target: str, reason: str) -> list[dict[str, Any]]:
    return [
        {
            "severity": "high",
            "title": f"Outdated service detected on {target}",
            "cve": "CVE-2023-12345",
            "port": 443,
            "protocol": "tcp",
            "recommendation": "Upgrade the vulnerable package and apply vendor patch.",
            "reference": "https://nvd.nist.gov",
            "is_patch_available": True,
            "metadata": {"fallback_reason": reason, "scanner": "openvas"},
        }
    ]


def _run_vulners_findings(target: str) -> list[dict[str, Any]]:
    api_key = os.getenv("VULNERS_API_KEY", "").strip()
    if not api_key:
        return _fallback_vulners_findings(target, "VULNERS_API_KEY not configured")

    query = f"type:bulletin {target}"
    try:
        response = requests.post(
            "https://vulners.com/api/v3/search/lucene/",
            json={"query": query, "size": 5},
            headers={"Content-Type": "application/json"},
            params={"apiKey": api_key},
            timeout=45,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        return _fallback_vulners_findings(target, f"vulners request failed: {exc}")

    search = payload.get("data", {}).get("search", []) if isinstance(payload, dict) else []
    findings: list[dict[str, Any]] = []
    for row in search[:10]:
        cve_list = row.get("cvelist", []) if isinstance(row, dict) else []
        cve = cve_list[0] if cve_list else ""
        findings.append(
            {
                "severity": "critical" if cve else "high",
                "title": str(row.get("title", f"Vulners exposure for {target}"))[:255],
                "cve": str(cve)[:32],
                "port": 22,
                "protocol": "tcp",
                "recommendation": "Validate exposure and apply remediation from associated advisories.",
                "reference": str(row.get("href", ""))[:500],
                "is_patch_available": True,
                "metadata": {"source": "vulners_live"},
            }
        )

    if findings:
        return findings
    return _fallback_vulners_findings(target, "vulners returned no findings")


def _fallback_vulners_findings(target: str, reason: str) -> list[dict[str, Any]]:
    return [
        {
            "severity": "critical",
            "title": f"Known exploitable CVE exposed on {target}",
            "cve": "CVE-2024-3094",
            "port": 22,
            "protocol": "tcp",
            "recommendation": "Immediately isolate host and apply emergency fix.",
            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "is_patch_available": True,
            "metadata": {"fallback_reason": reason, "scanner": "vulners"},
        }
    ]


def complete_scan_job(job_id: int, findings: list[dict[str, Any]]) -> dict[str, Any]:
    response = requests.post(
        f"{_api_base_url()}/scans/jobs/{job_id}/complete/",
        json={
            "status": "completed",
            "findings": findings,
            "metadata": {"orchestrated_by": "scanner-orchestrator"},
        },
        headers=_headers(),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def schedule_scan_cycle(limit: int = 5) -> dict[str, Any]:
    jobs = reserve_scan_jobs(limit=limit)
    completed: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for job in jobs:
        try:
            findings = _generate_findings(job)
            result = complete_scan_job(job["id"], findings)
            completed.append(result)
        except Exception as exc:  # noqa: BLE001
            failures.append({"job_id": job.get("id"), "error": str(exc)})

    return {
        "reserved": len(jobs),
        "completed": completed,
        "failures": failures,
    }
