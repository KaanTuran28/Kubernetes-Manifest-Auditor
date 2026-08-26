# Kubernetes Manifest Auditor

![CI](https://github.com/KaanTuran28/Kubernetes-Manifest-Auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static security auditor for Kubernetes workload manifests (Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob). No cluster access, no `kubectl` — just parses the YAML and flags the pod-security checklist a cluster-security review would apply by hand.

### Overview

- **Privileged containers** — `securityContext.privileged: true`.
- **Shared host namespaces** — `hostNetwork`/`hostPID`/`hostIPC: true`.
- **Dangerous added capabilities** — `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `SYS_PTRACE`, `SYS_MODULE`, `ALL`.
- **Risky `hostPath` mounts** — flags any hostPath volume, HIGH severity for especially sensitive paths (`/`, `/etc`, `/var/run/docker.sock`, ...).
- **Running as root** — no `runAsNonRoot: true` and no non-zero `runAsUser`.
- **`allowPrivilegeEscalation`** not explicitly `false` (Kubernetes' own default is to allow it).
- **Writable root filesystem** — no `readOnlyRootFilesystem: true`.
- **Missing resource limits** — no `resources.limits.cpu`/`.memory`.
- **Unpinned image tags** — no tag, or `:latest` (correctly ignores digest-pinned images and multi-stage-style registry ports).

Handles multi-document YAML (`---`-separated) and resolves the pod spec correctly for each workload kind (e.g. `Deployment.spec.template.spec`, `CronJob.spec.jobTemplate.spec.template.spec`).

### Installation

Requires Python 3.9+ and `PyYAML`.

```bash
git clone <this-repo>
cd Kubernetes-Manifest-Auditor
pip install -e .
```

This installs a `kubernetes-manifest-auditor` command. You can also run the script directly with `python kubernetes_manifest_auditor.py` after `pip install -r requirements.txt`.

### Usage

```bash
kubernetes-manifest-auditor --path deployment.yaml --output report.md
kubernetes-manifest-auditor --path ./k8s/ --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single manifest, or a directory to scan recursively for `*.yaml`/`*.yml` |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### CI Integration

Run this against every manifest change before it's applied to a cluster:

```bash
kubernetes-manifest-auditor --path ./k8s/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit Kubernetes manifests
  run: kubernetes-manifest-auditor --path ./k8s/ --fail-on high
```

### Example Output

[`sample_manifests/insecure_example.yaml`](./sample_manifests/insecure_example.yaml) demonstrates every check above; [`sample_manifests/hardened_example.yaml`](./sample_manifests/hardened_example.yaml) is its fixed counterpart (non-root, dropped capabilities, read-only root filesystem, resource limits, digest-pinned image) and produces **zero findings**. See [`sample_report.md`](./sample_report.md) — real output from scanning `insecure_example.yaml`: 4 HIGH, 4 MEDIUM, 1 LOW.

### Limitations

Static and heuristic — it audits what's declared in the manifest, not runtime behavior, admission-controller policy, or RBAC. It doesn't resolve Helm templates or Kustomize overlays (feed it their rendered output). Treat it as a fast pre-commit/CI pass, not a replacement for a full policy engine (OPA/Gatekeeper, Kyverno) enforced at admission time.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
Kubernetes-Manifest-Auditor/
├── kubernetes_manifest_auditor.py
├── pyproject.toml
├── sample_manifests/
│   ├── insecure_example.yaml
│   └── hardened_example.yaml
├── sample_report.md
├── tests/
│   └── test_kubernetes_manifest_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Kubernetes workload manifestleri (Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob) için statik bir güvenlik denetleyicisi. Küme erişimi veya `kubectl` gerektirmez — yalnızca YAML'ı parse eder ve bir küme güvenlik incelemesinin elle uygulayacağı pod-security kontrol listesini işaretler.

### Genel Bakış

- **Ayrıcalıklı (privileged) container'lar** — `securityContext.privileged: true`.
- **Paylaşılan host namespace'leri** — `hostNetwork`/`hostPID`/`hostIPC: true`.
- **Tehlikeli eklenen capability'ler** — `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `SYS_PTRACE`, `SYS_MODULE`, `ALL`.
- **Riskli `hostPath` mount'ları** — herhangi bir hostPath volume'unu işaretler, özellikle hassas yollar için (`/`, `/etc`, `/var/run/docker.sock`, ...) HIGH önem derecesi verir.
- **Root olarak çalışma** — `runAsNonRoot: true` yok ve sıfır olmayan bir `runAsUser` yok.
- **`allowPrivilegeEscalation`** açıkça `false` değil (Kubernetes'in kendi varsayılanı buna izin vermektir).
- **Yazılabilir root dosya sistemi** — `readOnlyRootFilesystem: true` yok.
- **Eksik kaynak limitleri** — `resources.limits.cpu`/`.memory` yok.
- **Sabitlenmemiş (unpinned) image tag'leri** — tag yok, veya `:latest` (digest ile sabitlenmiş image'ları ve multi-stage tarzı registry port'larını doğru şekilde göz ardı eder).

Çok belgeli (multi-document) YAML'ı (`---` ile ayrılmış) işler ve her workload türü için pod spec'ini doğru şekilde çözümler (ör. `Deployment.spec.template.spec`, `CronJob.spec.jobTemplate.spec.template.spec`).

### Kurulum

Python 3.9+ ve `PyYAML` gerektirir.

```bash
git clone <this-repo>
cd Kubernetes-Manifest-Auditor
pip install -e .
```

Bu, bir `kubernetes-manifest-auditor` komutu kurar. `pip install -r requirements.txt` sonrasında doğrudan `python kubernetes_manifest_auditor.py` ile de çalıştırabilirsiniz.

### Kullanım

```bash
kubernetes-manifest-auditor --path deployment.yaml --output report.md
kubernetes-manifest-auditor --path ./k8s/ --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir manifest, veya `*.yaml`/`*.yml` için özyinelemeli (recursive) olarak taranacak bir dizin |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde/üzerinde bir bulgu varsa çıkış kodu `1` |

### CI Entegrasyonu

Bunu, bir kümeye uygulanmadan önce her manifest değişikliğine karşı çalıştırın:

```bash
kubernetes-manifest-auditor --path ./k8s/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit Kubernetes manifests
  run: kubernetes-manifest-auditor --path ./k8s/ --fail-on high
```

### Örnek Çıktı

[`sample_manifests/insecure_example.yaml`](./sample_manifests/insecure_example.yaml) yukarıdaki tüm kontrolleri gösterir; [`sample_manifests/hardened_example.yaml`](./sample_manifests/hardened_example.yaml) bunun düzeltilmiş karşılığıdır (non-root, kaldırılmış capability'ler, salt okunur root dosya sistemi, kaynak limitleri, digest ile sabitlenmiş image) ve **sıfır bulgu** üretir. `insecure_example.yaml`'ın taranmasından elde edilen gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 4 HIGH, 4 MEDIUM, 1 LOW.

### Sınırlamalar

Statik ve sezgiseldir (heuristic) — manifestte deklare edileni denetler, çalışma zamanı davranışını, admission-controller politikasını veya RBAC'ı değil. Helm şablonlarını veya Kustomize overlay'lerini çözümlemez (bunların render edilmiş çıktısını verin). Bunu, admission zamanında uygulanan tam bir policy motorunun (OPA/Gatekeeper, Kyverno) yerine geçen bir şey değil, hızlı bir pre-commit/CI kontrolü olarak düşünün.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
Kubernetes-Manifest-Auditor/
├── kubernetes_manifest_auditor.py
├── pyproject.toml
├── sample_manifests/
│   ├── insecure_example.yaml
│   └── hardened_example.yaml
├── sample_report.md
├── tests/
│   └── test_kubernetes_manifest_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
