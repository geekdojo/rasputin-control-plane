# rasputin-author: the identity a later release adds store engines, policies
# and roles through (geekdojo/geekdojo-brain#1084; ADR-0010 S9, ruled
# 2026-11-15: a release may add engines and new policies with their own pinned
# identities, and never edits a policy created at first boot). rasputin-os's
# self-init loads it, bound to a role that admits the provisioner's leaf, and
# the store provisioner logs in with it for the items provision.tsv authors.
#
# The pinned disjoint-namespace shape #806 measured, inside rasputin-app-*:
#   - a mount's type is pinned to transit, and no other mount or tune
#     parameter passes, because there is no "*" key;
#   - policy text may be written only under the namespace;
#   - every role parameter is required or pinned: the CommonName stays inside
#     the namespace, token_policies and its alias policies bind only a
#     namespace policy, the default policy is dropped and the ttl fixed; the
#     denied "*,*" stops a second CommonName or policy in a comma list;
#   - there is no delete anywhere, so nothing can unmount an engine and
#     destroy every key in it.
# No glob reaches a fixed name (rasputin-api, -seal-rotate, -provisioner,
# -bindable, -author, root, default), and nothing grants root generation,
# rotation, audit, auth methods, tokens or data. storepolicy_test.go holds this
# text to exactly this shape.

path "sys/mounts/rasputin-app-*" {
  capabilities = ["read", "update"]
  allowed_parameters = {
    "type" = ["transit"]
  }
}

path "sys/policies/acl/rasputin-app-*" {
  capabilities = ["read", "create", "update"]
}

path "auth/cert/certs/rasputin-app-*" {
  capabilities = ["update"]
  required_parameters = ["certificate", "allowed_common_names", "token_policies", "token_no_default_policy", "token_ttl"]
  allowed_parameters = {
    "certificate"             = []
    "allowed_common_names"    = ["rasputin-app-*"]
    "token_policies"          = ["rasputin-app-*"]
    "policies"                = ["rasputin-app-*"]
    "token_no_default_policy" = ["true"]
    "token_ttl"               = ["1h"]
  }
  denied_parameters = {
    "allowed_common_names" = ["*,*"]
    "token_policies"       = ["*,*"]
    "policies"             = ["*,*"]
  }
}
