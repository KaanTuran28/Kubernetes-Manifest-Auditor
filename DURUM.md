# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Kubernetes workload manifest'lerini (Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob) statik denetleyen CLI aracı. Portföyde ilk kez gerçek bir bağımlılık (`PyYAML`) kullanıldı — YAML'ı elle regex ile ayrıştırmak yerine (Dockerfile/Terraform/nginx projelerindeki gibi) doğru YAML semantiği (multi-document, tip dönüşümleri) gerektiği için bilinçli bir tercih.
- Denetimler: privileged container, hostNetwork/hostPID/hostIPC, tehlikeli capability ekleme (SYS_ADMIN vb.), root olarak çalışma, allowPrivilegeEscalation varsayılanı, salt-okunur olmayan root filesystem, kaynak limiti eksikliği, riskli hostPath mount'ları (özellikle `/`, `/etc`, docker.sock gibi hassas yollar için HIGH), pinlenmemiş image tag.
- Test sırasında gerçek bir bug yakalandı ve düzeltildi: hostPath `path: "/"` denetiminde `path.rstrip("/")` çağrısı "/" için boş string üretiyordu, bu da SENSITIVE_HOSTPATHS setindeki "/" ile hiç eşleşmiyordu — yani en kritik durum (tüm host root dosya sistemi mount edilmesi) yanlışlıkla sadece MEDIUM olarak işaretleniyordu, HIGH olması gerekirken. `normalized_path = path.rstrip("/") or "/"` ile düzeltildi ve testle doğrulandı.
- Dosya: `kubernetes_manifest_auditor.py`, 2 örnek manifest (`insecure_example.yaml` — 9 kontrolün hepsini bir arada gösteriyor, `hardened_example.yaml` — 0 bulgu), `tests/test_kubernetes_manifest_auditor.py` (34 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 34/34 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI her iki örneğe karşı gerçekten çalıştırıldı: `insecure_example.yaml` → 4 HIGH + 4 MEDIUM + 1 LOW, `hardened_example.yaml` → 0 bulgu. `sample_report.md` gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Kubernetes-Manifest-Auditor` adıyla repo aç, git init + push.
