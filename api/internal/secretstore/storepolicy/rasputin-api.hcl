# rasputin-api: the api's fixed policy in the node secrets store
# (geekdojo/geekdojo-brain#804; ADR-0010 S9). rasputin-control-plane owns this
# text; the api release tarball carries it to the image as openbao-policy/, and
# the store's self-init loads it from there.
#
# Least privilege: create, read, update and delete on secret data under apps/
# and devices/, read and delete on their metadata, and a read of the token's
# own lookup. Nothing else: no sys/, no identity/, no token creation, no sudo,
# no list, destroy, undelete or patch. Business authorization is the api's own
# service (#761); this is the store's second layer.

path "rasputin-secrets/data/apps/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "rasputin-secrets/data/devices/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "rasputin-secrets/metadata/apps/*" {
  capabilities = ["read", "delete"]
}

path "rasputin-secrets/metadata/devices/*" {
  capabilities = ["read", "delete"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
