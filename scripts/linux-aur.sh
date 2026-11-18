#!/usr/bin/env bash
set -euo pipefail
version=${1:?version}
dist=$(realpath "${2:?artifacts}")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
mkdir -p "$dist/aur"
cp packaging/linux/netswitch.install packaging/linux/netswitch-*.hook "$dist/aur/"
cat > "$dist/aur/PKGBUILD" <<EOF
pkgname=netswitch-bin
pkgver=$version
pkgrel=1
pkgdesc='Choose which internet connection each app uses'
arch=('x86_64' 'aarch64')
url='https://github.com/kekawia/net-switch'
license=('MIT')
depends=('systemd' 'dbus' 'xdg-utils' 'iproute2')
provides=('netswitch')
conflicts=('netswitch')
install=netswitch.install
options=('!strip')
source=('netswitch-upgrade.hook' 'netswitch-remove.hook')
sha512sums=('$(sha512sum packaging/linux/netswitch-upgrade.hook | cut -d' ' -f1)' '$(sha512sum packaging/linux/netswitch-remove.hook | cut -d' ' -f1)')
EOF
for entry in x86_64:amd64 aarch64:arm64; do
    arch=${entry%:*}
    file=netswitch-$version-${entry#*:}.tar.gz
    sum=$(sha512sum "$dist/$file" | cut -d' ' -f1)
    printf "source_%s=('https://github.com/kekawia/net-switch/releases/download/v%s/%s')\nsha512sums_%s=('%s')\n" "$arch" "$version" "$file" "$arch" "$sum" >> "$dist/aur/PKGBUILD"
done
cat >> "$dist/aur/PKGBUILD" <<'EOF'
package() {
    cp -a "$srcdir/usr" "$pkgdir/"
    install -Dm644 -t "$pkgdir/usr/share/libalpm/hooks/" "$srcdir/"netswitch-*.hook
}
EOF
