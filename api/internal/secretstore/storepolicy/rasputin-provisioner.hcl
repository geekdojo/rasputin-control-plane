# rasputin-provisioner: the store provisioner's fixed policy in the node
# secrets store (geekdojo/geekdojo-brain#805; ADR-0010 S9). rasputin-os's
# rasputin-store-provision oneshot logs in with it on every store start and
# adds the kv-v2 mounts and cert roles a later release's provision.tsv lists.
#
# Binding-only. It adds mounts and roles inside one namespace, rasputin-rel-*,
# and binds a role only to the one pre-shipped policy rasputin-bindable. It
# authors no policy and touches no fixed mount, role or policy:
#   - no "*" key, so every role parameter not listed below is refused;
#   - token_policies and its alias policies are each pinned to one string;
#   - required_parameters makes every role write carry the token policy,
#     token_no_default_policy=true and the ttl;
#   - the denied "*,*" stops a second CommonName under the namespace glob;
#   - the mount type is pinned, so no tune parameter passes, and there is no
#     delete.
# It grants nothing on policies, rotation, root generation, raft storage,
# audit, auth methods, identity, tokens or any secret data, and neither glob
# covers a fixed mount, role or policy name. storepolicy_test.go holds this
# text to exactly this shape.

path "sys/mounts/rasputin-rel-*" {
  capabilities = ["read", "update"]
  allowed_parameters = {
    "type" = ["kv-v2"]
  }
}

path "auth/cert/certs/" {
  capabilities = ["list"]
}

path "auth/cert/certs/rasputin-rel-*" {
  capabilities = ["update"]
  required_parameters = ["certificate", "allowed_common_names", "token_policies", "token_no_default_policy", "token_ttl"]
  allowed_parameters = {
    "certificate"             = []
    "allowed_common_names"    = ["rasputin-rel-*"]
    "token_policies"          = ["rasputin-bindable"]
    "policies"                = ["rasputin-bindable"]
    "token_no_default_policy" = ["true"]
    "token_ttl"               = ["1h"]
  }
  denied_parameters = {
    "allowed_common_names" = ["*,*"]
  }
}
