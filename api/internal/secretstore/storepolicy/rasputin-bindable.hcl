# rasputin-bindable: the one policy a provisioned role may bind
# (geekdojo/geekdojo-brain#805, D-805-A; ADR-0010 S9). A lookup of the token's
# own self and nothing else, so a role the provisioner adds grants nothing
# until S9's privileged step changes this text (#806).

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
