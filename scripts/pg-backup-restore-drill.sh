#!/usr/bin/env bash
set -euo pipefail

# M10.5 PostgreSQL Backup, Restore, RLS & Audit-Immutability Verification Drill

PG_CONTAINER="${PG_CONTAINER:-deploy-postgres-1}"
PG_USER="${PG_USER:-operquay}"
PG_DB="${PG_DB:-operquay}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5454}"
DRILL_DB="operquay_restore_drill_$$"
DUMP_FILE="$(mktemp "${TMPDIR:-/tmp}/operquay-pg-drill-XXXXXX.sql")"

run_psql() {
  local target_db="$1"
  shift
  if command -v podman >/dev/null 2>&1 && podman ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
    podman exec -i "${PG_CONTAINER}" psql -p "${PG_PORT}" -U "${PG_USER}" -d "${target_db}" -v ON_ERROR_STOP=1 "$@"
  else
    PGPASSWORD="${PGPASSWORD:-operquay_dev_change_me}" psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${target_db}" -v ON_ERROR_STOP=1 "$@"
  fi
}

run_pg_dump() {
  if command -v podman >/dev/null 2>&1 && podman ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
    podman exec "${PG_CONTAINER}" pg_dump -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" --clean --if-exists --no-owner > "${DUMP_FILE}"
  else
    PGPASSWORD="${PG_PASSWORD:-operquay_dev_change_me}" pg_dump -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" --clean --if-exists --no-owner > "${DUMP_FILE}"
  fi
}

cleanup() {
  set +e
  run_psql postgres -c "DROP DATABASE IF EXISTS ${DRILL_DB};" >/dev/null 2>&1
  rm -f "${DUMP_FILE}"
}
trap cleanup EXIT

echo "[1/5] Dumping live PostgreSQL database '${PG_DB}'..."
pre_audit_cnt="$(run_psql "${PG_DB}" -tAc "SELECT COUNT(*) FROM audit_events;" | tr -d ' ')"
run_pg_dump
post_audit_cnt="$(run_psql "${PG_DB}" -tAc "SELECT COUNT(*) FROM audit_events;" | tr -d ' ')"
dump_bytes="$(wc -c < "${DUMP_FILE}" | tr -d ' ')"
if [ "${dump_bytes}" -lt 512 ]; then
  echo "ERROR: dump file unexpectedly small (${dump_bytes} bytes)"
  exit 1
fi
echo "      Dump size: ${dump_bytes} bytes (primary audit_events window: ${pre_audit_cnt}..${post_audit_cnt})"

echo "[2/5] Creating isolated restore database '${DRILL_DB}' and restoring..."
run_psql postgres -c "CREATE DATABASE ${DRILL_DB};" >/dev/null
run_psql "${DRILL_DB}" < "${DUMP_FILE}" >/dev/null

echo "[3/5] Verifying restored audit_events integrity against primary snapshot..."
dst_audit_cnt="$(run_psql "${DRILL_DB}" -tAc "SELECT COUNT(*) FROM audit_events;" | tr -d ' ')"
if [ "${dst_audit_cnt}" -lt "${pre_audit_cnt}" ] || [ "${dst_audit_cnt}" -gt "${post_audit_cnt}" ]; then
  echo "ERROR: audit_events count outside dump snapshot window (window=${pre_audit_cnt}..${post_audit_cnt}, restored=${dst_audit_cnt})"
  exit 1
fi
echo "      audit_events count matched snapshot: ${dst_audit_cnt}"

echo "[4/5] Verifying FORCE ROW LEVEL SECURITY across M10 tables..."
rls_missing="$(run_psql "${DRILL_DB}" -tAc "
  SELECT COUNT(*) FROM (
    VALUES
      ('recording_metadata'),
      ('aws_sso_sessions'),
      ('aws_role_leases'),
      ('aws_discovery_inventory'),
      ('aws_user_saved_inventory'),
      ('tenant_encryption_keys')
  ) AS req(name)
  LEFT JOIN pg_class c ON c.relname = req.name AND c.relnamespace = 'public'::regnamespace
  WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity;
" | tr -d ' ')"
if [ "${rls_missing}" != "0" ]; then
  echo "ERROR: ${rls_missing} M10 tables missing ENABLE/FORCE ROW LEVEL SECURITY in restored DB"
  exit 1
fi
echo "      All 6 new M10 tables enforce FORCE ROW LEVEL SECURITY"

echo "[5/5] Verifying immutable audit_events enforcement under operquay_app..."
if run_psql "${DRILL_DB}" -c "SET ROLE operquay_app; UPDATE audit_events SET action = 'tamper';" >/dev/null 2>&1; then
  echo "ERROR: UPDATE on audit_events succeeded under operquay_app!"
  exit 1
fi
if run_psql "${DRILL_DB}" -c "SET ROLE operquay_app; DELETE FROM audit_events;" >/dev/null 2>&1; then
  echo "ERROR: DELETE on audit_events succeeded under operquay_app!"
  exit 1
fi
echo "      Immutable audit_events trigger/privilege block confirmed."
echo "PASS: PostgreSQL backup/restore & security drill completed cleanly."
