#!/usr/bin/env bash
set -euo pipefail
version=${1:?version}
dist=$(realpath "${2:?artifacts}")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
mkdir -p "$dist/aur"
cp packaging/linux/netswitch.install "$dist/aur/"
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
}
EOF
