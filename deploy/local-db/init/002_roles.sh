#!/bin/sh
# PostgREST logs in as "authenticator" and switches to the role named in the
# request's JWT (pii_writer). The password comes from the container environment.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v authenticator_password="$PII_DB_AUTHENTICATOR_PASSWORD" <<'SQL'
create role authenticator login noinherit password :'authenticator_password';
grant pii_writer to authenticator;
SQL
