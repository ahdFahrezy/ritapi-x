#!/bin/sh
set -e

host="$1"
shift
cmd="$@"

echo "Menunggu Postgres di $host:$POSTGRES_PORT ..."

until PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$host" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q'; do
  >&2 echo "Postgres belum siap - menunggu..."
  sleep 2
done

>&2 echo "Postgres siap — menjalankan perintah selanjutnya..."
sh -c "$cmd"
