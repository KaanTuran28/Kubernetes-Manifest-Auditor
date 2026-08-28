#!/usr/bin/env python3
"""Static security auditor for Kubernetes workload manifests (YAML).

Parses Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob
manifests (multi-document YAML supported) and flags the checks a
cluster-security review would apply by hand: privileged containers, shared
host namespaces, dangerous added capabilities, containers running as root,
missing resource limits, risky hostPath mounts, and unpinned image tags.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE"}
SENSITIVE_HOSTPATHS = {"/", "/etc", "/var/run/docker.sock", "/root", "/proc", "/boot"}
WORKLOAD_KINDS_WITH_TEMPLATE = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}


def extract_pod_spec(doc: dict):
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec")
    if kind in WORKLOAD_KINDS_WITH_TEMPLATE:
        return (doc.get("spec") or {}).get("template", {}).get("spec")
    if kind == "CronJob":
        job_template = (doc.get("spec") or {}).get("jobTemplate", {})
        return (job_template.get("spec") or {}).get("template", {}).get("spec")
    return None


def finding(severity: str, resource: str, check: str, reason: str, recommendation: str) -> dict:
    return {
        "severity": severity, "resource": resource, "check": check,
        "reason": reason, "recommendation": recommendation,
    }


def has_unpinned_tag(image: str) -> bool:
    if "@sha256:" in image:
        return False
    tag_part = image.rsplit("/", 1)[-1]
    return ":" not in tag_part or tag_part.rsplit(":", 1)[-1] == "latest"


def audit_manifest(doc: dict) -> list:
    if not isinstance(doc, dict):
        return []

    kind = doc.get("kind", "?")
    name = (doc.get("metadata") or {}).get("name", "?")
    label = f"{kind}/{name}"

    pod_spec = extract_pod_spec(doc)
    if pod_spec is None:
        return []

    findings = []
    pod_security_context = pod_spec.get("securityContext") or {}

    shared_namespaces = [k for k in ("hostNetwork", "hostPID", "hostIPC") if pod_spec.get(k) is True]
    if shared_namespaces:
        findings.append(finding(
            "HIGH", label, "host_namespace_sharing",
            f"Pod shares the host's {', '.join(shared_namespaces)} namespace(s), breaking isolation "
            "from the host (processes/network/IPC visible across the boundary).",
            "Remove hostNetwork/hostPID/hostIPC unless there is a specific, reviewed need for it.",
        ))

    for vol in pod_spec.get("volumes") or []:
        if not isinstance(vol, dict):
            continue
        host_path = vol.get("hostPath")
        if not host_path:
            continue
        path = host_path.get("path", "")
        vol_name = vol.get("name", "?")
        normalized_path = path.rstrip("/") or "/"
        severity = "HIGH" if normalized_path in SENSITIVE_HOSTPATHS else "MEDIUM"
        findings.append(finding(
            severity, label, "hostpath_volume_mount",
            f'Volume "{vol_name}" mounts host path "{path}" into the pod.',
            "Avoid hostPath; use a PersistentVolumeClaim or a narrower, purpose-built volume type instead.",
        ))

    containers = (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])
    for container in containers:
        if not isinstance(container, dict):
            continue
        cname = container.get("name", "?")
        clabel = f"{label}/{cname}"
        sc = container.get("securityContext") or {}

        if sc.get("privileged") is True:
            findings.append(finding(
                "HIGH", clabel, "privileged_container",
                "securityContext.privileged is true — the container has essentially full access to the host.",
                "Remove privileged: true; grant only the specific capabilities actually required.",
            ))

        added_caps = {str(c).upper() for c in (sc.get("capabilities") or {}).get("add") or []}
        dangerous = sorted(added_caps & DANGEROUS_CAPABILITIES)
        if dangerous:
            findings.append(finding(
                "HIGH", clabel, "dangerous_capability_added",
                f"Adds dangerous capability(ies): {', '.join(dangerous)}.",
                "Drop ALL capabilities by default and add back only the minimal specific ones required.",
            ))

        run_as_non_root = sc.get("runAsNonRoot", pod_security_context.get("runAsNonRoot"))
        run_as_user = sc.get("runAsUser", pod_security_context.get("runAsUser"))
        if run_as_non_root is not True and (run_as_user is None or run_as_user == 0):
            findings.append(finding(
                "MEDIUM", clabel, "running_as_root",
                "No runAsNonRoot: true (and no non-zero runAsUser) — the container can run as root inside "
                "its own namespace, widening the impact of a container-escape vulnerability.",
                "Set securityContext.runAsNonRoot: true and a specific non-zero runAsUser.",
            ))

        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(finding(
                "MEDIUM", clabel, "allow_privilege_escalation",
                "allowPrivilegeEscalation is not explicitly set to false (Kubernetes defaults to allowing it).",
                "Set securityContext.allowPrivilegeEscalation: false.",
            ))

        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(finding(
                "LOW", clabel, "writable_root_filesystem",
                "readOnlyRootFilesystem is not true — a compromised process can modify the container's own filesystem.",
                "Set securityContext.readOnlyRootFilesystem: true, and mount an emptyDir for any path that "
                "genuinely needs to be writable.",
            ))

        resources = container.get("resources") or {}
        limits = resources.get("limits") or {}
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(finding(
                "MEDIUM", clabel, "missing_resource_limits",
                "No cpu/memory resources.limits set — this container can consume unbounded node resources, "
                "starving other workloads (noisy-neighbor / DoS risk).",
                "Set resources.limits.cpu and resources.limits.memory appropriate to the workload.",
            ))

        image = container.get("image", "")
        if image and has_unpinned_tag(image):
            findings.append(finding(
                "MEDIUM", clabel, "unpinned_image_tag",
                f'Image "{image}" is unpinned (no tag, or ":latest") — the running image can change '
                "unexpectedly between rollouts.",
                "Pin to a specific version tag or, better, a content digest (@sha256:...).",
            ))

    return findings


def audit_file(text: str) -> list:
    docs = [d for d in yaml.safe_load_all(text) if d]
    findings = []
    for doc in docs:
        findings.extend(audit_manifest(doc))
    return findings


def build_report(results: list) -> str:
    all_findings = [(f, source) for source, findings in results for f in findings]
    high = [f for f, _ in all_findings if f["severity"] == "HIGH"]
    medium = [f for f, _ in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f, _ in all_findings if f["severity"] == "LOW"]

    lines = [
        "# Kubernetes Manifest Security Audit",
        "",
        f"- **Files scanned:** {len(results)}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW",
        "",
    ]
    if all_findings:
        lines += ["| Severity | File | Resource | Check | Reason |", "|---|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f, source in sorted(all_findings, key=lambda pair: order[pair[0]["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {source} | {f['resource']} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(results: list) -> str:
    all_findings = [f for _, findings in results for f in findings]
    payload = {
        "files_scanned": len(results),
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        },
        "results": [{"file": source, "findings": findings} for source, findings in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def collect_yaml_files(path: Path) -> list:
    if path.is_file():
        return [path]
    files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
    return sorted(set(files))


def main():
    parser = argparse.ArgumentParser(description="Static security audit of Kubernetes workload manifests.")
    parser.add_argument("--path", required=True, help="Path to a YAML manifest or a directory to scan recursively.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    files = collect_yaml_files(target)
    results = [(str(f), audit_file(f.read_text(encoding="utf-8"))) for f in files]

    report = build_json_report(results) if args.format == "json" else build_report(results)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    all_findings = [f for _, findings in results for f in findings]
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"Scanned {len(files)} file(s): {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
