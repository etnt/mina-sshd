#!/bin/sh
# Generate host keys on first start, set the test user password, run sshd.
set -e
K=/etc/ssh
[ -f $K/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519    -N '' -f $K/ssh_host_ed25519_key
[ -f $K/ssh_host_mldsa44_key ] || ssh-keygen -q -t ssh-mldsa-44 -N '' -f $K/ssh_host_mldsa44_key
[ -f $K/ssh_host_mldsa65_key ] || ssh-keygen -q -t ssh-mldsa-65 -N '' -f $K/ssh_host_mldsa65_key
[ -f $K/ssh_host_mldsa87_key ] || ssh-keygen -q -t ssh-mldsa-87 -N '' -f $K/ssh_host_mldsa87_key
echo "test:${TEST_PASSWORD:-test}" | chpasswd
exec /opt/ssh/sbin/sshd -D -e "$@"
