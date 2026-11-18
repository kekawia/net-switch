#!/usr/bin/env bash
# Run the shipped package in a disposable distribution VM with systemd as PID 1.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
family=${1:?rpm or arch}; files=$(realpath "${2:?artifacts}")
case $family in
    rpm) image=https://download.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2
         sha=50bdc5e70f6a24f540932d15411c1c6ae9fcfa40fb990d876d83c5cc823b2ad0 ;;
    arch) image=https://geo.mirror.pkgbuild.com/images/v20261115.625457/Arch-Linux-x86_64-cloudimg-20261115.625457.qcow2
          sha=dbd02830f6eb0fe07ef6e5edaddbae8b577ce4296d9e79118904704cce0a1f60 ;;
    *) exit 2 ;;
esac
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils ovmf ipxe-qemu
work=$(mktemp -d); chmod 700 "$work"
sudo setfacl -m u:"$(id -un)":rw /dev/kvm
curl -fLsS "$image" -o "$work/disk"
echo "$sha  $work/disk" | sha256sum -c -
qemu-img resize -f qcow2 "$work/disk" 20G
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cat > "$work/user-data" <<EOF
#cloud-config
users:
  - name: nsrunner
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
ssh_pwauth: false
EOF
printf 'instance-id: ns-package-test\n' > "$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars"
qemu-system-x86_64 -accel kvm -cpu host -smp 2 -m 3500 -display none -serial "file:$work/serial" -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive "if=pflash,format=raw,file=$work/vars" \
    -drive "if=virtio,format=qcow2,file=$work/disk" -drive "if=virtio,format=raw,file=$work/seed.img" \
    -nic user,model=virtio,hostfwd=tcp:127.0.0.1:2222-:22 &
vm=$!
trap 'rc=$?; if ((rc)); then tail -120 "$work/serial"; fi; kill "$vm" 2>/dev/null || :; wait "$vm" || :; rm -rf "$work"' EXIT
args=(-i "$work/key" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=3 -o UserKnownHostsFile="$work/known" -o StrictHostKeyChecking=accept-new)
remote=(ssh "${args[@]}" -p 2222 nsrunner@127.0.0.1)
end=$((SECONDS+240))
until "${remote[@]}" true; do kill -0 "$vm"; (( SECONDS < end )) || exit 1; sleep 2; done
"${remote[@]}" 'sudo cloud-init status --wait && mkdir -p /tmp/ns-pkgs'
scp -P 2222 "${args[@]}" scripts/package-smoke.sh nsrunner@127.0.0.1:/tmp/smoke
if [[ $family == arch ]]; then
    scp -P 2222 "${args[@]}" -r "$files"/aur-* "$files"/*-amd64.tar.gz nsrunner@127.0.0.1:/tmp/ns-pkgs/
    "${remote[@]}" 'set -e
        sudo pacman --noconfirm -Syu --needed base-devel sudo iproute2 xdg-utils
        for v in 1.0.1 1.0.2; do
            cd "/tmp/ns-pkgs/aur-$v"
            SRCDEST=/tmp/ns-pkgs PKGDEST=/tmp/ns-pkgs makepkg --noconfirm --cleanbuild
            makepkg --printsrcinfo > .SRCINFO
        done'
else
    scp -P 2222 "${args[@]}" -r "$files/repo" nsrunner@127.0.0.1:/tmp/ns-pkgs/
    "${remote[@]}" 'sudo dnf -y install rpm-sign'
fi
"${remote[@]}" "sudo env NETSWITCH_PACKAGE_SMOKE=disposable bash /tmp/smoke $family /tmp/ns-pkgs" || {
    "${remote[@]}" 'sudo journalctl -u netswitch.service -u netswitch-engine.service -n 100 --no-pager'
    exit 1
}
