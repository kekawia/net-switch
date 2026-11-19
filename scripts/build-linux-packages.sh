#!/usr/bin/env bash
# Build the same staged native binaries into each distribution format.
set -euo pipefail
repo=$(git rev-parse --show-toplevel)
cd "$repo"
version=${1:?stable version required}
out=$(realpath -m "${2:?output directory required}")
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || exit 2
host=$(go env GOHOSTARCH)
arch=${3:-$host}
formats=${4:-all}
[[ "$formats" == all || "$formats" == deb ]] || exit 2
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
case $host in
  amd64) archive=x86_64; digest=2afaa5ffb5e3493402e31e7c67a5a1fb42133e3f66fc315ca0051934125561c7 ;;
  arm64) archive=arm64; digest=d4eee71839e92c68cbd3b101640bad32d2856fc551acae0635be9118e48c9d9c ;;
  *) exit 2 ;;
esac
export PACKAGE_VERSION="$version" GOARCH="$arch" CGO_ENABLED=0
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$out"
curl --fail --silent --show-error --location -o "$work/nfpm.tgz" "https://github.com/goreleaser/nfpm/releases/download/v2.49.0/nfpm_2.49.0_Linux_${archive}.tar.gz"
(cd "$work"; echo "$digest  nfpm.tgz" | sha256sum -c -; tar xzf nfpm.tgz nfpm)
root="$work/root"
bin="$root/usr/lib/netswitch"
units="$root/usr/lib/systemd/system"
licenses="$root/usr/share/licenses/netswitch"
mkdir -p "$bin" "$units" "$licenses" "$root/usr/bin" "$work/hooks"
for name in netswitch netswitchctl netswitch-engine netswitch-desktop; do
    go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/kekawia/net-switch/internal/buildinfo.Version=$version" -o "$bin/$name" "./cmd/$name"
done
node scripts/engine-notices.mjs "$bin/netswitch-engine" --check
for unit in netswitch.service netswitch-engine.service netswitch.socket; do
    GOARCH="$host" go run ./cmd/netswitchctl package unit "$unit" > "$units/$unit"
done
ln -s /usr/lib/netswitch/netswitch-desktop "$root/usr/bin/netswitch"
ln -s /usr/lib/netswitch/netswitchctl "$root/usr/bin/netswitchctl"
install -Dm644 ui/favicon.svg "$root/usr/share/icons/hicolor/scalable/apps/netswitch.svg"
install -Dm644 packaging/linux/netswitch.desktop "$root/usr/share/applications/netswitch.desktop"
install -Dm644 docs/user-guide.md "$root/usr/share/doc/netswitch/user-guide.md"
install -m644 THIRD_PARTY_NOTICES.md LICENSE "$licenses/"
for file in "$(go env GOROOT)/LICENSE" "$(go env GOROOT)/PATENTS"; do install -m644 "$file" "$licenses/go-$(basename "$file")"; done
install -m644 licenses/lucide-ISC.txt internal/usage/*LICENSE.txt "$licenses/"
install -Dm644 third_party/gvisor/AUTHORS "$licenses/gvisor-AUTHORS"
while read -r module; do
    install -Dm644 "vendor/$module/LICENSE" "$licenses/vendor/$module/LICENSE"
done < <(for exe in "$bin/"*; do go version -m "$exe"; done | awk '$1=="dep"{print $2}' | sort -u)
install -m755 packaging/linux/{deb,rpm}-* "$work/hooks/"
cp packaging/linux/nfpm.yaml "$work/"
(cd "$work"
    ./nfpm package -f nfpm.yaml -p deb -t "$out/netswitch-${version}-${arch}.deb"
    if [[ "$formats" == all ]]; then
        ./nfpm package -f nfpm.yaml -p rpm -t "$out/netswitch-${version}-${arch}.rpm"
    fi
)
if [[ "$formats" == all ]]; then
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$root" -czf "$out/netswitch-${version}-${arch}.tar.gz" usr
fi
