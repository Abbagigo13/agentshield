#!/usr/bin/env bash
# Free database backup: dumps PostgreSQL to a timestamped .sql.gz file.
# Usage:
#   DATABASE_PUBLIC_URL=postgresql://... ./scripts/backup-db.sh
# Get DATABASE_PUBLIC_URL from Railway: Postgres service -> Variables.
# (DATABASE_URL also works if it points at a publicly reachable database.)
# Requires Docker. Restore with:
#   gunzip -c backups/<file>.sql.gz | psql "$DATABASE_PUBLIC_URL"
set -euo pipefail

URL="${DATABASE_PUBLIC_URL:-${DATABASE_URL:-}}"
if [ -z "$URL" ]; then
  echo "ERROR: set DATABASE_PUBLIC_URL (Railway: Postgres service -> Variables)." >&2
  exit 1
fi
case "$URL" in
  *.railway.internal*) echo "ERROR: that is the internal Railway URL; use DATABASE_PUBLIC_URL instead." >&2; exit 1 ;;
esac

mkdir -p backups
FILE="backups/agentshield-$(date +%Y%m%d-%H%M%S).sql.gz"
echo "Backing up to $FILE ..."
docker run --rm postgres:18-alpine pg_dump "$URL" | gzip > "$FILE"
echo "Done: $FILE ($(du -h "$FILE" | cut -f1))"
echo "Keep this file somewhere safe (it contains your full database). Never commit it."
