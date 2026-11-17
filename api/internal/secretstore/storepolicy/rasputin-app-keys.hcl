# rasputin-app-keys: the api's key identity in the node secrets store
# (geekdojo/geekdojo-brain#1084; ADR-0010 S9). The store provisioner writes it
# from this file, logged in as rasputin-author, and binds it to the role of the
# same name, which admits only the api's key leaf (CommonName
# rasputin-app-keys). The api uses that identity for an app's Transit keys
# and nothing else; its kv identity, rasputin-api, is unchanged.
#
# Least privilege on the one mount rasputin-app-keys, each path exactly one
# segment deep ("+"), so no stanza reaches a key's sub-paths:
#   - create a key, with only its type, pinned, and delete it;
#   - set deletion_allowed, the one config change a delete needs;
#   - encrypt and decrypt under an existing key. There is no create on
#     encrypt, so an encrypt can never make a key the api's index lacks.
# Nothing else: no rotate, trim, import, other config, read, list, export,
# backup, restore, datakey, rewrap, auth/ or sys/. Business authorization is
# the api's own service; this is the store's second layer.

path "rasputin-app-keys/keys/+" {
  capabilities = ["update", "delete"]
  allowed_parameters = {
    "type" = ["aes256-gcm96"]
  }
}

path "rasputin-app-keys/keys/+/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "deletion_allowed" = ["true"]
  }
}

path "rasputin-app-keys/encrypt/+" {
  capabilities = ["update"]
}

path "rasputin-app-keys/decrypt/+" {
  capabilities = ["update"]
}
