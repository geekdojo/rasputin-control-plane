# rasputin-seal-rotate: the seal rotation job's fixed policy in the node
# secrets store (geekdojo/geekdojo-brain#804, #830; ADR-0010 S9, S10).
#
# "Only sudo on sys/rotate/root" reads as sudo on that one path plus the update
# capability its endpoint needs: sys/rotate/root is a sudo path, and an ACL
# needs both the operation's capability and sudo. The policy functional test
# shows a sudo-only and an update-only policy are each refused.

path "sys/rotate/root" {
  capabilities = ["update", "sudo"]
}
