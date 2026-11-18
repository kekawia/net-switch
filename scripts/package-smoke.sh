#!/usr/bin/env bash
# Invoked only on a disposable systemd runner/guest. $2 contains both package versions.
set -euo pipefail
family=${1:?deb, rpm or arch}; files=$(realpath "${2:?package artifacts}")
[[ $(id -u) == 0 && ${NETSWITCH_PACKAGE_SMOKE:-} == disposable ]]
[[ ! -e /var/lib/netswitch && ! -e /usr/lib/netswitch ]]
pkgarch=$(uname -m); case $pkgarch in x86_64) arch=amd64;; aarch64) arch=arm64;; *) exit 2;; esac
ctl=/usr/lib/netswitch/netswitchctl
data=/var/lib/netswitch
socket=netswitch.socket
unit=netswitch.service
owner=nspackageuser
useradd --create-home "$owner"
trap 'loginctl disable-linger "$owner" || :; userdel -r "$owner" || :' EXIT
loginctl enable-linger "$owner"
if [[ "$family" == rpm ]]; then
    [[ $(getenforce) == Enforcing ]]
    pkg="$files/repo/netswitch-1.0.1-$arch.rpm"
    # Require an actual signature failure before importing the test repo key.
    reject_signature() {
        if rpmkeys --define '_pkgverify_level signature' --checksig --verbose "$1" > /tmp/ns-signature.log 2>&1; then
            cat /tmp/ns-signature.log; echo 'Accepted an untrusted package' >&2; exit 1
        fi
        cat /tmp/ns-signature.log
    }
    reject_signature "$pkg"
    cp "$pkg" /tmp/ns-unsigned.rpm
    rpmsign --delsign /tmp/ns-unsigned.rpm
    reject_signature /tmp/ns-unsigned.rpm
    rpmkeys --import "$files/repo/netswitch.asc"
    rpmkeys --define '_pkgverify_level signature' --checksig --verbose "$pkg"
    cat > /etc/yum.repos.d/netswitch-test.repo <<EOF
[netswitch-test]
name=Net Switch disposable repo
baseurl=file://$files/repo
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$files/repo/netswitch.asc
EOF
fi
install_version() {
    case $family in
      deb) apt-get -y install "$files/netswitch-$1-$arch.deb" ;;
      rpm) dnf -y --refresh install "netswitch-$1-1" ;;
      arch) pacman --noconfirm -U "$files/netswitch-bin-$1-1-$pkgarch.pkg.tar.zst" ;;
      *) return 2 ;;
    esac
}
remove_package() {
    case $family in
      deb) dpkg --purge netswitch ;;
      rpm) dnf -y remove netswitch ;;
      arch) pacman --noconfirm -R netswitch-bin ;;
    esac
}
install_version 1.0.1
test "$(stat -c '%a:%u' "$data")" = '700:0'
systemctl is-active --quiet "$socket"
test ! -e "$data/owner.json"
if [[ "$family" == deb ]]; then
    proof=$files/package-$arch.test
    install -m755 "$proof" /usr/local/bin/ns-package-proof
    env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted NETSWITCH_LIFECYCLE_CI=1 NETSWITCH_TEST_DEB="$files/netswitch-1.0.2-$arch.deb" \
      /usr/local/bin/ns-package-proof -test.v -test.run='^TestInstalledDebUpgradeWithLiveRouting$' -test.timeout=5m | tee /tmp/ns-package-proof.log
    grep -F 'PACKAGE_TRAFFIC previous_and_replacement_echo=true' /tmp/ns-package-proof.log
    remove_package
    install_version 1.0.1
fi
"$ctl" enroll --owner "$owner"
systemctl start "$unit"
before=$(systemctl show -p MainPID --value "$unit")
test "$before" -gt 1
test "$(systemctl show -p FragmentPath --value "$unit")" = "/usr/lib/systemd/system/$unit" || test "$(realpath "$(systemctl show -p FragmentPath --value "$unit")")" = "/usr/lib/systemd/system/$unit"
systemctl show -p ExecStopPost netswitch-engine.service | grep -F 'cleanup --engine'
ownerhash=$(sha256sum "$data/owner.json")
install -d /etc/systemd/system/netswitch.service.d
printf '[Service]\nEnvironment=NETSWITCH_PACKAGE_TEST=yes\n' > /etc/systemd/system/netswitch.service.d/smoke.conf
install_version 1.0.2
after=$(systemctl show -p MainPID --value "$unit")
test "$after" -gt 1
test "$before" != "$after"
"$ctl" version | grep -F '1.0.2'
test "$(sha256sum "$data/owner.json")" = "$ownerhash"
test -f /etc/systemd/system/netswitch.service.d/smoke.conf
test ! -e "$data/package-maintenance"
"$ctl" status
remove_package
test ! -e "$ctl"
test -f "$data/owner.json"
test "$(sha256sum "$data/owner.json")" = "$ownerhash"
if systemctl is-active --quiet "$unit" || systemctl is-active --quiet "$socket"; then
    echo 'Package removal left a unit active' >&2; exit 1
fi
test -f /etc/systemd/system/netswitch.service.d/smoke.conf
install_version 1.0.1
systemctl disable --now "$socket"
install_version 1.0.2
if systemctl is-active --quiet "$socket" || systemctl is-enabled --quiet "$socket"; then
    echo 'Upgrade reactivated a disabled socket' >&2; exit 1
fi
remove_package
echo "PACKAGE_SMOKE family=$family arch=$arch install=pass upgrade=pass owner=retained dropin=retained removal=pass"
