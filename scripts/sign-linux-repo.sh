#!/usr/bin/env bash
# Run with Fedora's rpm tools. Only the finished signed repo leaves this job.
set -euo pipefail
export LC_ALL=C
out=$(realpath "${1:?artifact directory}")
mode=${2:?test or release}
export GNUPGHOME=$(mktemp -d)
trap 'gpgconf --kill all || :; rm -rf -- "$GNUPGHOME"' EXIT
if [[ "$mode" == test ]]; then
    gpg --batch --pinentry-mode loopback --passphrase '' --cert-digest-algo SHA512 --quick-generate-key "Net Switch disposable package test" rsa3072 sign 1d
elif [[ "$mode" == release ]]; then
    : "${NETSWITCH_RPM_KEY:?provide the armored release signing key}"
    : "${NETSWITCH_RPM_FINGERPRINT:?provide the pinned release fingerprint}"
    printf '%s\n' "$NETSWITCH_RPM_KEY" | gpg --batch --import
    unset NETSWITCH_RPM_KEY
else exit 2
fi
mapfile -t keys < <(gpg --with-colons --list-secret-keys | awk -F: '$1=="sec"{want=1} $1=="fpr" && want{print $10;want=0}')
[[ ${#keys[@]} -eq 1 ]]
fpr=${keys[0]}
if [[ "$mode" == release ]]; then [[ "$fpr" == "$NETSWITCH_RPM_FINGERPRINT" ]]; fi
repo="$out/repo"
mkdir -p "$repo"
install -m644 packaging/linux/netswitch.repo "$repo/netswitch.repo"
gpg --export --armor "$fpr" > "$repo/netswitch.asc"
gpg --list-packets "$repo/netswitch.asc" | awk '/digest algo/{n++;if ($3+0 != 10) bad=1} END{exit (!n || bad)}'
for pkg in "$out"/*.rpm; do
    rpmsign --define '_openpgp_sign gpg' --define "_openpgp_sign_id $fpr" --define '_gpg_digest_algo sha512' --addsign "$pkg"
    cp "$pkg" "$repo/"
done
db="$GNUPGHOME/rpmdb"
rpmkeys --dbpath "$db" --import "$repo/netswitch.asc"
for pkg in "$repo"/*.rpm; do
    rpmkeys --dbpath "$db" --checksig --verbose "$pkg" | tee "$GNUPGHOME/check"
    grep -Ei 'RSA/SHA512.*signature.*OK' "$GNUPGHOME/check"
done
createrepo_c "$repo"
gpg --batch --local-user "$fpr" --digest-algo SHA512 --armor --detach-sign "$repo/repodata/repomd.xml"
gpg --verify "$repo/repodata/repomd.xml.asc" "$repo/repodata/repomd.xml"
