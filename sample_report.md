# Kubernetes Manifest Security Audit

- **Files scanned:** 1
- **Findings:** 4 HIGH, 4 MEDIUM, 1 LOW

| Severity | File | Resource | Check | Reason |
|---|---|---|---|---|
| HIGH | sample_manifests\insecure_example.yaml | Deployment/legacy-app | host_namespace_sharing | Pod shares the host's hostNetwork namespace(s), breaking isolation from the host (processes/network/IPC visible across the boundary). |
| HIGH | sample_manifests\insecure_example.yaml | Deployment/legacy-app | hostpath_volume_mount | Volume "host-root" mounts host path "/" into the pod. |
| HIGH | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | privileged_container | securityContext.privileged is true — the container has essentially full access to the host. |
| HIGH | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | dangerous_capability_added | Adds dangerous capability(ies): SYS_ADMIN. |
| MEDIUM | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | running_as_root | No runAsNonRoot: true (and no non-zero runAsUser) — the container can run as root inside its own namespace, widening the impact of a container-escape vulnerability. |
| MEDIUM | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | allow_privilege_escalation | allowPrivilegeEscalation is not explicitly set to false (Kubernetes defaults to allowing it). |
| MEDIUM | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | missing_resource_limits | No cpu/memory resources.limits set — this container can consume unbounded node resources, starving other workloads (noisy-neighbor / DoS risk). |
| MEDIUM | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | unpinned_image_tag | Image "nginx" is unpinned (no tag, or ":latest") — the running image can change unexpectedly between rollouts. |
| LOW | sample_manifests\insecure_example.yaml | Deployment/legacy-app/app | writable_root_filesystem | readOnlyRootFilesystem is not true — a compromised process can modify the container's own filesystem. |
