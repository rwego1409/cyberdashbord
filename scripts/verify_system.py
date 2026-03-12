import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    payload: Any = None


@dataclass
class Verifier:
    base_url: str
    debug_role: str
    results: list[CheckResult] = field(default_factory=list)
    token: str | None = None
    consent_id: str | None = None
    scan_job_id: int | None = None

    def _record(self, name: str, ok: bool, detail: str = "", payload: Any = None) -> None:
        self.results.append(CheckResult(name=name, ok=ok, detail=detail, payload=payload))

    def _headers(self, auth: bool = False, debug: bool = False) -> dict[str, str]:
        headers: dict[str, str] = {}
        if auth and self.token:
            headers["Authorization"] = f"Token {self.token}"
        if debug:
            headers["X-Debug-Role"] = self.debug_role
        return headers

    def run(self) -> int:
        self.check_health()
        self.check_auth_bootstrap_and_token()
        self.check_consent_create_and_list()
        self.check_scan_queue_and_process()
        self.check_scan_findings_and_progress()
        self.check_scan_queue_async()
        self.check_osint_ingest_and_list()
        self.check_osint_sources_health()
        self.check_analytics_generate_and_list()
        self.check_alert_dispatch_and_ack()
        self.check_reports_and_exports()
        self.check_system_metrics()
        self.check_admin_interfaces()
        self.check_audit_logs()
        return self.report()

    def check_health(self) -> None:
        name = "health"
        try:
            r = requests.get(f"{self.base_url}/health/", timeout=20)
            ok = r.status_code == 200 and r.json().get("status") == "ok"
            self._record(name, ok, f"status={r.status_code}", r.json())
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_auth_bootstrap_and_token(self) -> None:
        name = "auth_bootstrap_token"
        username = f"verify_{int(dt.datetime.now(dt.timezone.utc).timestamp())}"
        payload = {
            "username": username,
            "password": "Verify123!",
            "role": "analyst",
            "organization": "TCIO Verify",
        }
        try:
            boot = requests.post(
                f"{self.base_url}/authn/bootstrap/",
                json=payload,
                headers=self._headers(debug=True),
                timeout=20,
            )
            boot_data = boot.json()
            self.token = boot_data.get("token")
            login = requests.post(
                f"{self.base_url}/authn/token/",
                json={"username": username, "password": "Verify123!"},
                timeout=20,
            )
            login_data = login.json()
            if not self.token:
                self.token = login_data.get("token")
            ok = boot.status_code in (200, 201) and login.status_code == 200 and bool(self.token)
            self._record(name, ok, f"bootstrap={boot.status_code} login={login.status_code}", {"bootstrap": boot_data, "login": login_data})
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_consent_create_and_list(self) -> None:
        name = "consent_create_list"
        valid_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).isoformat()
        body = {
            "requester_name": "Verifier",
            "requester_email": "verify@example.com",
            "target": "198.51.100.77",
            "allowed_scanners": ["nmap", "openvas", "vulners"],
            "valid_until": valid_until,
            "source": "manual",
        }
        try:
            create = requests.post(
                f"{self.base_url}/consent/grants/",
                json=body,
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            create_data = create.json()
            self.consent_id = create_data.get("consent_id")
            listing = requests.get(f"{self.base_url}/consent/grants/list/?limit=10", timeout=20)
            list_data = listing.json()
            ok = create.status_code == 201 and bool(self.consent_id) and listing.status_code == 200
            self._record(name, ok, f"create={create.status_code} list={listing.status_code}", {"create": create_data, "list": list_data})
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_scan_queue_and_process(self) -> None:
        name = "scan_queue_process"
        if not self.consent_id:
            self._record(name, False, "missing consent_id")
            return
        create_body = {
            "consent_id": self.consent_id,
            "asset_type": "ip",
            "asset_value": "198.51.100.77",
            "scanner_type": "nmap",
            "requested_by": "verifier",
        }
        try:
            create = requests.post(
                f"{self.base_url}/scans/jobs/",
                json=create_body,
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            create_data = create.json()
            self.scan_job_id = create_data.get("scan_job_id")
            process = requests.post(
                f"{self.base_url}/scans/jobs/process-once/",
                json={"limit": 10},
                headers=self._headers(auth=True, debug=True),
                timeout=40,
            )
            process_data = process.json()
            summary = requests.get(f"{self.base_url}/scans/summary/", timeout=20)
            summary_data = summary.json()
            ok = create.status_code == 201 and process.status_code == 200 and summary.status_code == 200
            self._record(
                name,
                ok,
                f"create={create.status_code} process={process.status_code} summary={summary.status_code}",
                {"create": create_data, "process": process_data, "summary": summary_data},
            )
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_scan_queue_async(self) -> None:
        name = "scan_queue_async"
        try:
            response = requests.post(
                f"{self.base_url}/scans/jobs/process-async/",
                json={"limit": 5},
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            payload = response.json()
            ok = response.status_code == 202 and payload.get("status") == "queued" and bool(payload.get("task_id"))
            self._record(name, ok, f"status={response.status_code}", payload)
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_scan_findings_and_progress(self) -> None:
        name = "scan_findings_progress"
        if not self.scan_job_id:
            self._record(name, False, "missing scan_job_id")
            return
        try:
            findings = requests.get(f"{self.base_url}/scans/findings/?limit=20", timeout=20)
            findings_data = findings.json()
            progress = requests.get(f"{self.base_url}/scans/jobs/{self.scan_job_id}/progress/", timeout=20)
            progress_data = progress.json()
            ok = (
                findings.status_code == 200
                and progress.status_code == 200
                and "severity_distribution" in findings_data
                and "progress" in progress_data
            )
            self._record(
                name,
                ok,
                f"findings={findings.status_code} progress={progress.status_code}",
                {"findings": findings_data, "progress": progress_data},
            )
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_osint_ingest_and_list(self) -> None:
        name = "osint_ingest_list"
        body = {
            "source": "nvd",
            "event_type": "cve_disclosure",
            "occurred_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "country_code": "TZ",
            "region": "Dodoma",
            "district": "Dodoma Urban",
            "ward": "Nzuguni",
            "indicator": "cve",
            "value": "CVE-2026-0001",
            "severity_score": 7.9,
            "raw_payload": {"verification": True},
        }
        try:
            ingest = requests.post(
                f"{self.base_url}/osint/events/ingest/",
                json=body,
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            ingest_data = ingest.json()
            listing = requests.get(f"{self.base_url}/osint/events/?limit=20", timeout=20)
            list_data = listing.json()
            ok = ingest.status_code == 201 and listing.status_code == 200
            self._record(name, ok, f"ingest={ingest.status_code} list={listing.status_code}", {"ingest": ingest_data, "list": list_data})
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_osint_sources_health(self) -> None:
        name = "osint_sources_health"
        try:
            response = requests.get(f"{self.base_url}/osint/sources-health/", timeout=20)
            payload = response.json()
            sources = payload.get("sources", [])
            has_tzcert = any(source.get("source") == "tzcert" for source in sources)
            has_nvd = any(source.get("source") == "nvd" for source in sources)
            ok = response.status_code == 200 and has_tzcert and has_nvd
            self._record(name, ok, f"status={response.status_code} sources={len(sources)}", payload)
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_analytics_generate_and_list(self) -> None:
        name = "analytics_snapshots"
        try:
            gen = requests.post(
                f"{self.base_url}/analytics/snapshots/generate/",
                json={},
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            gen_data = gen.json()
            listing = requests.get(f"{self.base_url}/analytics/snapshots/?limit=20", timeout=20)
            list_data = listing.json()
            risk = requests.get(f"{self.base_url}/analytics/risk-overview/", timeout=20)
            risk_data = risk.json()
            ok = gen.status_code == 200 and listing.status_code == 200 and risk.status_code == 200
            self._record(name, ok, f"generate={gen.status_code} list={listing.status_code} risk={risk.status_code}", {"generate": gen_data, "list": list_data, "risk": risk_data})
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_alert_dispatch_and_ack(self) -> None:
        name = "alerts_dispatch_ack"
        try:
            dispatch = requests.post(
                f"{self.base_url}/alerts/dispatch/",
                json={"limit": 20},
                headers=self._headers(auth=True, debug=True),
                timeout=20,
            )
            dispatch_data = dispatch.json()
            active = requests.get(f"{self.base_url}/alerts/active/", timeout=20)
            active_data = active.json()
            ack_status = 200
            if active_data.get("active"):
                first_id = active_data["active"][0]["id"]
                ack = requests.post(
                    f"{self.base_url}/alerts/{first_id}/ack/",
                    json={},
                    headers=self._headers(auth=True, debug=True),
                    timeout=20,
                )
                ack_status = ack.status_code
            ok = dispatch.status_code == 200 and active.status_code == 200 and ack_status in (200, 404)
            self._record(name, ok, f"dispatch={dispatch.status_code} active={active.status_code} ack={ack_status}", {"dispatch": dispatch_data, "active": active_data})
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_reports_and_exports(self) -> None:
        name = "reports_exports"
        try:
            summary = requests.get(f"{self.base_url}/reports/summary/", timeout=20)
            summary_data = summary.json()
            json_export = requests.get(f"{self.base_url}/reports/export/?type=scan&format=json", timeout=20)
            csv_export = requests.get(f"{self.base_url}/reports/export/?type=scan&format=csv", timeout=20)
            pdf_export = requests.get(f"{self.base_url}/reports/export/?type=scan&format=pdf", timeout=20)
            ok = (
                summary.status_code == 200
                and json_export.status_code == 200
                and csv_export.status_code == 200
                and pdf_export.status_code == 200
                and "scan_report" in summary_data
            )
            self._record(
                name,
                ok,
                f"summary={summary.status_code} json={json_export.status_code} csv={csv_export.status_code} pdf={pdf_export.status_code}",
                {"summary": summary_data},
            )
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_system_metrics(self) -> None:
        name = "system_metrics"
        try:
            response = requests.get(f"{self.base_url}/system/metrics/", timeout=20)
            payload = response.json()
            ok = response.status_code == 200 and "metrics" in payload and "services" in payload
            self._record(name, ok, f"status={response.status_code}", payload)
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_admin_interfaces(self) -> None:
        name = "admin_interfaces"
        try:
            users = requests.get(f"{self.base_url}/authn/users/", headers=self._headers(debug=True), timeout=20)
            orgs = requests.get(f"{self.base_url}/authn/organizations/", headers=self._headers(debug=True), timeout=20)
            api_keys = requests.get(f"{self.base_url}/authn/api-keys/", headers=self._headers(debug=True), timeout=20)
            ok = users.status_code == 200 and orgs.status_code == 200 and api_keys.status_code == 200
            self._record(
                name,
                ok,
                f"users={users.status_code} orgs={orgs.status_code} api_keys={api_keys.status_code}",
                {
                    "users_count": len(users.json().get("users", [])) if users.status_code == 200 else None,
                    "orgs_count": len(orgs.json().get("organizations", [])) if orgs.status_code == 200 else None,
                    "api_keys_count": len(api_keys.json().get("keys", [])) if api_keys.status_code == 200 else None,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def check_audit_logs(self) -> None:
        name = "audit_logs"
        try:
            r = requests.get(f"{self.base_url}/audit/logs/?limit=20", timeout=20)
            data = r.json()
            ok = r.status_code == 200 and "logs" in data
            self._record(name, ok, f"status={r.status_code} logs={len(data.get('logs', []))}", data)
        except Exception as exc:  # noqa: BLE001
            self._record(name, False, str(exc))

    def report(self) -> int:
        passed = [r for r in self.results if r.ok]
        failed = [r for r in self.results if not r.ok]

        print("=== TCIO Verification Report ===")
        print(f"Base URL: {self.base_url}")
        print(f"Passed: {len(passed)}  Failed: {len(failed)}")
        for r in self.results:
            state = "PASS" if r.ok else "FAIL"
            print(f"[{state}] {r.name} :: {r.detail}")
        if failed:
            print("\nFailure details:")
            for f in failed:
                print(json.dumps({"name": f.name, "detail": f.detail, "payload": f.payload}, default=str))
            return 1
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TCIO integration verification harness")
    parser.add_argument("--base-url", default="http://localhost:8001/api/v1")
    parser.add_argument("--debug-role", default="analyst")
    args = parser.parse_args()

    verifier = Verifier(base_url=args.base_url.rstrip("/"), debug_role=args.debug_role)
    return verifier.run()


if __name__ == "__main__":
    raise SystemExit(main())
