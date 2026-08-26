import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kubernetes_manifest_auditor import (
    audit_file,
    audit_manifest,
    build_json_report,
    build_report,
    collect_yaml_files,
    extract_pod_spec,
    has_unpinned_tag,
    main,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_manifests"


def checks_in(findings):
    return [f["check"] for f in findings]


def audit_sample(name):
    return audit_file((SAMPLES / name).read_text(encoding="utf-8"))


def load_yaml(text):
    return yaml.safe_load(text)


def test_extract_pod_spec_for_pod():
    doc = load_yaml("kind: Pod\nspec:\n  containers: []\n")
    assert extract_pod_spec(doc) == {"containers": []}


def test_extract_pod_spec_for_deployment():
    doc = load_yaml("kind: Deployment\nspec:\n  template:\n    spec:\n      containers: []\n")
    assert extract_pod_spec(doc) == {"containers": []}


def test_extract_pod_spec_for_cronjob():
    doc = load_yaml(
        "kind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers: []\n"
    )
    assert extract_pod_spec(doc) == {"containers": []}


def test_extract_pod_spec_returns_none_for_unknown_kind():
    doc = load_yaml("kind: ConfigMap\ndata: {}\n")
    assert extract_pod_spec(doc) is None


def test_has_unpinned_tag_no_tag():
    assert has_unpinned_tag("nginx") is True


def test_has_unpinned_tag_latest():
    assert has_unpinned_tag("nginx:latest") is True


def test_has_unpinned_tag_pinned_version():
    assert has_unpinned_tag("nginx:1.25.3-alpine") is False


def test_has_unpinned_tag_pinned_digest():
    assert has_unpinned_tag("nginx@sha256:" + "a" * 64) is False


def test_has_unpinned_tag_registry_with_port_not_false_positive():
    assert has_unpinned_tag("registry.example.com:5000/team/app:1.2.3") is False


def test_privileged_container_flagged_high():
    doc = load_yaml("kind: Pod\nspec:\n  containers:\n  - name: c\n    securityContext:\n      privileged: true\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "privileged_container" and f["severity"] == "HIGH" for f in findings)


def test_dangerous_capability_flagged_high():
    doc = load_yaml(
        "kind: Pod\nspec:\n  containers:\n  - name: c\n    securityContext:\n"
        "      capabilities:\n        add: [\"SYS_ADMIN\"]\n"
    )
    findings = audit_manifest(doc)
    assert any(f["check"] == "dangerous_capability_added" for f in findings)


def test_harmless_capability_not_flagged():
    doc = load_yaml(
        "kind: Pod\nspec:\n  containers:\n  - name: c\n    securityContext:\n"
        "      capabilities:\n        add: [\"NET_BIND_SERVICE\"]\n"
    )
    findings = audit_manifest(doc)
    assert not any(f["check"] == "dangerous_capability_added" for f in findings)


def test_host_namespace_sharing_flagged_high():
    doc = load_yaml("kind: Pod\nspec:\n  hostNetwork: true\n  containers: []\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "host_namespace_sharing" and f["severity"] == "HIGH" for f in findings)


def test_hostpath_root_flagged_high():
    doc = load_yaml(
        "kind: Pod\nspec:\n  volumes:\n  - name: v\n    hostPath:\n      path: /\n  containers: []\n"
    )
    findings = audit_manifest(doc)
    hp = [f for f in findings if f["check"] == "hostpath_volume_mount"]
    assert len(hp) == 1 and hp[0]["severity"] == "HIGH"


def test_hostpath_non_sensitive_flagged_medium():
    doc = load_yaml(
        "kind: Pod\nspec:\n  volumes:\n  - name: v\n    hostPath:\n      path: /data/app\n  containers: []\n"
    )
    findings = audit_manifest(doc)
    hp = [f for f in findings if f["check"] == "hostpath_volume_mount"]
    assert len(hp) == 1 and hp[0]["severity"] == "MEDIUM"


def test_running_as_root_flagged_when_no_security_context():
    doc = load_yaml("kind: Pod\nspec:\n  containers:\n  - name: c\n    image: nginx:1.25\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "running_as_root" for f in findings)


def test_running_as_non_root_true_not_flagged():
    doc = load_yaml(
        "kind: Pod\nspec:\n  containers:\n  - name: c\n    securityContext:\n"
        "      runAsNonRoot: true\n      runAsUser: 1000\n"
    )
    findings = audit_manifest(doc)
    assert not any(f["check"] == "running_as_root" for f in findings)


def test_allow_privilege_escalation_default_flagged_medium():
    doc = load_yaml("kind: Pod\nspec:\n  containers:\n  - name: c\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "allow_privilege_escalation" for f in findings)


def test_allow_privilege_escalation_false_not_flagged():
    doc = load_yaml(
        "kind: Pod\nspec:\n  containers:\n  - name: c\n    securityContext:\n      allowPrivilegeEscalation: false\n"
    )
    findings = audit_manifest(doc)
    assert not any(f["check"] == "allow_privilege_escalation" for f in findings)


def test_missing_resource_limits_flagged_medium():
    doc = load_yaml("kind: Pod\nspec:\n  containers:\n  - name: c\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "missing_resource_limits" for f in findings)


def test_resource_limits_present_not_flagged():
    doc = load_yaml(
        "kind: Pod\nspec:\n  containers:\n  - name: c\n    resources:\n"
        "      limits:\n        cpu: \"500m\"\n        memory: \"256Mi\"\n"
    )
    findings = audit_manifest(doc)
    assert not any(f["check"] == "missing_resource_limits" for f in findings)


def test_unpinned_image_flagged_medium():
    doc = load_yaml("kind: Pod\nspec:\n  containers:\n  - name: c\n    image: nginx\n")
    findings = audit_manifest(doc)
    assert any(f["check"] == "unpinned_image_tag" for f in findings)


def test_non_workload_kind_returns_no_findings():
    doc = load_yaml("kind: ConfigMap\ndata:\n  key: value\n")
    assert audit_manifest(doc) == []


def test_insecure_example_flags_expected_checks_and_counts():
    findings = audit_sample("insecure_example.yaml")
    checks = set(checks_in(findings))
    assert checks == {
        "host_namespace_sharing",
        "hostpath_volume_mount",
        "privileged_container",
        "dangerous_capability_added",
        "running_as_root",
        "allow_privilege_escalation",
        "writable_root_filesystem",
        "missing_resource_limits",
        "unpinned_image_tag",
    }
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    assert (high, medium, low) == (4, 4, 1)


def test_hardened_example_has_no_findings():
    assert audit_sample("hardened_example.yaml") == []


def test_multi_document_yaml_audits_each_document():
    text = (SAMPLES / "insecure_example.yaml").read_text(encoding="utf-8") + "\n---\n" + \
        (SAMPLES / "hardened_example.yaml").read_text(encoding="utf-8")
    findings = audit_file(text)
    assert len(findings) == 9


def test_collect_yaml_files_on_directory():
    files = collect_yaml_files(SAMPLES)
    names = {f.name for f in files}
    assert names == {"insecure_example.yaml", "hardened_example.yaml"}


def test_collect_yaml_files_on_single_file():
    assert len(collect_yaml_files(SAMPLES / "hardened_example.yaml")) == 1


def test_build_report_lists_findings_in_markdown_table():
    results = [("insecure_example.yaml", audit_sample("insecure_example.yaml"))]
    report = build_report(results)
    assert "HIGH" in report
    assert "privileged_container" in report


def test_build_report_clean_says_no_issues():
    results = [("hardened_example.yaml", audit_sample("hardened_example.yaml"))]
    report = build_report(results)
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    results = [("insecure_example.yaml", audit_sample("insecure_example.yaml"))]
    payload = json.loads(build_json_report(results))
    assert payload["files_scanned"] == 1
    assert payload["summary"]["high"] == 4


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["kubernetes_manifest_auditor.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_insecure_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.yaml", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_hardened_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "hardened_example.yaml", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.yaml", []) == 0
