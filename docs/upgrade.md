# Vigil 0.5.0 to 1.0.0 Upgrade Runbook

This guide covers upgrading existing Vigil SOC deployments from version `0.5.x` to `1.0.0`.

---

## 1. Prerequisites & Backup

Before applying database migrations, take a complete logical backup of your PostgreSQL database:

```bash
pg_dump -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -Fc -f vigil-backup-0.5.0.dump
```

---

## 2. Alembic Migration Engine

Starting in Vigil 1.0, database schema migrations are managed via **Alembic**.

The migration sequence builds upon the `0001_baseline_0_5_0` revision:
1. `0001_baseline_0_5_0`: Reflects the existing 0.5.0 baseline schema.
2. `0002_ledger_grants`: Establishes `vigil_app` (SELECT/INSERT only on `agent_events`) and `vigil_admin` roles.
3. `0003_ledger_hash`: Adds `prev_hash` and `event_hash` to `agent_events` for tamper evidence.
4. `0004_policies`: Creates the `policies` table and migrates autonomy/budget/suppression thresholds.
5. `0005_artifacts`: Creates the hash-addressed `artifacts` table.
6. `0006_coverage_view`: Creates the `coverage` SQL view over `agent_events`.
7. `0007_suppression_view`: Creates the `suppression_candidates` SQL view over verdicts.

---

## 3. Applying Migrations

### For Existing 0.5.0 Deployments:
If your database already contains the 0.5.0 tables created via SQL init scripts, stamp the baseline and upgrade to head:

```bash
# Stamp 0.5.0 baseline
alembic stamp 0001_baseline_0_5_0

# Run all 1.0 migrations to head
alembic upgrade head
```

### For Clean / New Deployments:
Running `./start.sh` or applying Helm charts will automatically initialize and run migrations:

```bash
alembic upgrade head
```

---

## 4. Verification

Verify that all tables and views are present and the ledger hash chain is intact:

```bash
# Verify ledger integrity
vigil ledger verify

# Verify schema head
alembic current
```

---

## 5. Rollback Plan

In the event of an unrecoverable failure during upgrade:
1. Revert application deployment to version 0.5.0 image tags.
2. Downgrade database schema:
   ```bash
   alembic downgrade 0001_baseline_0_5_0
   ```
3. Restore from pre-upgrade database backup if table data was modified.

---

## 6. Authentication & Roles Bootstrap

In Vigil 1.0, release images enforce authentication by default (`DEV_MODE=false`).
For existing installations upgrading from 0.5.0, run:

```bash
vigil auth bootstrap --user admin
```

This outputs a one-time bootstrap credential for initial login. Default credentials (`admin/admin123`) require forced rotation on first login and cannot be reused.

Role privileges enforced at the route layer:
- **`admin`**: Full system administration, policy loosening, integration configuration.
- **`analyst`**: Triage, hunt, candidate authoring, and containment actions. Cannot loosen policy.
- **`viewer`**: Read-only observation across all views. Cannot call action tools or alter detections.

---

## 7. External Database & Redis Setup

For production Kubernetes environments with managed cloud infrastructure:
1. Disable in-chart Postgres and Redis:
   ```yaml
   postgresql:
     enabled: false
     external:
       host: "aurora-pg.internal.corp"
       port: 5432
       database: "deeptempo_soc"
       username: "deeptempo"
       existingSecret: "vigil-pg-secret"
       existingSecretKey: "POSTGRES_PASSWORD"

   redis:
     enabled: false
     external:
       url: "redis://elasticache.internal.corp:6379/0"
   ```
2. Enable Horizontal Pod Autoscaling (HPA) on worker nodes:
   - Target CPU Utilization: `80%`
   - Scrape annotations: `prometheus.io/scrape: "true"`
   ```yaml
   llmWorker:
     autoscaling:
       enabled: true
       targetCPUUtilizationPercentage: 80
   agentWorker:
     autoscaling:
       enabled: true
       targetCPUUtilizationPercentage: 80
   ```

---

## 8. Design-Partner Cluster Validation Runbook

Step-by-step verification procedure executed on candidate partner clusters:
1. **Migration Integrity**:
   ```bash
   kubectl exec -it deployment/vigil-backend -- alembic current
   kubectl exec -it deployment/vigil-backend -- vigil ledger verify
   ```
2. **HPA Status**:
   ```bash
   kubectl get hpa -l app.kubernetes.io/name=vigil
   ```
   Verify targets show `cpu: <current>% / 80%`.
3. **Prometheus Metrics Ingest**:
   Verify Prometheus discovers targets:
   ```bash
   curl -s http://vigil-backend:6987/metrics | grep vigil_work_total
   ```
4. **Dry Run Execution**:
   ```bash
   kubectl exec -it deployment/vigil-backend -- vigil dryrun --scenario redrun_v1
   ```
   Verify scorecard is emitted and hash-addressed in `artifacts` table.
