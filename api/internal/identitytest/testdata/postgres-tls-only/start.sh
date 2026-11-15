#!/bin/sh
# TestPostgresTLSOnly's entrypoint (geekdojo/geekdojo-brain#972). As root it
# stands in for LoadCredential=: the server's certificate, key and CA go into
# /run/credentials/keycloak-db.service/ owned by postgres at 0400, in a
# directory it owns at 0500 (the shape #679 Q2 measured, #958's fill_creds).
# Then, as postgres, it initialises a cluster, creates the role and database
# keycloak, and runs the server on postgresql.conf.
set -eu
cred=/run/credentials/keycloak-db.service
mkdir -p "$cred"
install -o postgres -g postgres -m 0400 /src/server/leaf.pem "$cred/server.pem"
install -o postgres -g postgres -m 0400 /src/server/leaf.key "$cred/server.key"
install -o postgres -g postgres -m 0400 /src/ca.pem "$cred/identity-ca.pem"
chown postgres:postgres "$cred"
chmod 0500 "$cred"
data=/var/lib/postgresql/data # on the tmpfs, which root owns
install -d -o postgres -g postgres -m 0700 "$data"
gosu postgres initdb -D "$data" >/dev/null
printf 'CREATE ROLE keycloak LOGIN;\nCREATE DATABASE keycloak OWNER keycloak;\n' |
	gosu postgres postgres --single -D "$data" postgres >/dev/null
exec gosu postgres postgres -D "$data" -c config_file=/etc/rasputin/identity/postgresql.conf
