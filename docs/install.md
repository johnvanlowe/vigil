# Vigil 1.0 Installation & Verification Guide

## 1. Fast Start (Ten-Minute Install)

### Option A: Local / Evaluation (`start.sh`)
Clone the repository and run the local development/eval launcher:

```bash
git clone https://github.com/johnvanlowe/vigil.git
cd vigil
./start.sh
```

- By default, `./start.sh` boots in developer mode with an authentication bypass banner for evaluation.
- To run with full authentication enforced:
  ```bash
  ./start.sh --auth
  ```
- To run the unattended closed-loop dry run:
  ```bash
  ./start.sh --dryrun
  ```

### Option B: Docker Compose

```bash
docker compose -f infra/docker/docker-compose.yml up -d
```

### Option C: Kubernetes / Helm
See `infra/helm/vigil/` for production Kubernetes deployments.

---

## 2. Supply Chain Security & Image Verification (Cosign)

All official release container images published to GitHub Packages (`ghcr.io/vigil-soc/*`) are signed keylessly using Sigstore Cosign via GitHub Actions OIDC tokens.

### Verifying Image Signatures

To verify the signature of any release image:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/Vigil-SOC/vigil/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/vigil-soc/vigil-backend:1.0.0
```

Repeat for companion images:
```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/Vigil-SOC/vigil/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/vigil-soc/vigil-daemon:1.0.0
```

If the signature or digest does not match the official repository identity, `cosign verify` exits non-zero and refuses execution.

---

## 3. Initial Access & Bootstrap

On a clean release installation (`DEV_MODE=false`), bootstrap administrative credentials:

```bash
vigil auth bootstrap --user admin
```

The initial password (`admin123`) enforces immediate credential rotation on first login and cannot be reused.

---

## 4. Next Steps & Architecture Links
- [Headless & MCP Server Operations](headless.md)
- [Policy Engine & Autonomy Tiers](policies.md)
- [Metrics Registry & Alerts](metrics.md)
- [Deprecation Policy](deprecation.md)
- [Contributing Guide](contributing.md)
