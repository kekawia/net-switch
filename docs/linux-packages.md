# Linux packages

For a Net Switch release that includes Linux packages, choose the file for your processor. On Debian and Ubuntu, use the `.deb` file. On Fedora, use the signed RPM repository. On Arch, the `netswitch-bin` recipe builds a package from the release archive and verifies its SHA-512 checksum.

On Debian or Ubuntu, open a terminal in the download directory and run `sudo apt install ./NAME.deb`, replacing `NAME.deb` with the downloaded filename. Use the same command with the new version's file to upgrade.

Once the Fedora repository is published, add it with `sudo dnf5 config-manager addrepo --from-repofile=https://kekawia.github.io/net-switch/netswitch.repo`, then run `sudo dnf install netswitch`. Check the fingerprint offered by DNF against the release maintainer's fingerprint before accepting the key. Subsequent versions arrive with normal DNF upgrades.

After installing, enroll the person who will control routing. From that person's terminal, run `sudo netswitchctl enroll "$USER"`. Then open Net Switch from the applications menu. The activation socket starts the service when you open the app. Your service settings and owner record live in the protected directory `/var/lib/netswitch`.

Use your package manager for upgrades and removal. An upgrade briefly stops routing while it replaces the installed programs. It keeps your owner, settings and current routing choice. Removing the package stops its services and keeps your saved data for a later install.

## Building and distributing packages

On an amd64 or arm64 Linux host with the Go version from go.mod, run `bash scripts/build-linux-packages.sh VERSION OUTPUT ARCH` for each architecture. The staging directory contains the four Go programs, the same systemd units as the manual install plus their maintenance check, the applications menu entry and licenses. The build verifies the downloaded nFPM executable archive. Build intermediates are private until the signing job succeeds.

Release publication requires the ASCII-armored signing secret `NETSWITCH_RPM_KEY`, its independently configured public fingerprint `NETSWITCH_RPM_FINGERPRINT`, and GitHub Pages configured with Actions as its publication source. Use a dedicated unattended RPM signing key. Its certifications and package signatures must use SHA-512. The test workflow generates a temporary key on the runner. The release workflow verifies the configured fingerprint and publishes the signed packages, repository metadata, public key and Arch recipe for the tagged version.

Verify the RPM repository key fingerprint against the release maintainer's independently distributed fingerprint before importing it. The repository requires both metadata and package signature checks. The Arch recipe and matching binary archives are GitHub release assets. Extract the recipe as an ordinary user and run `makepkg -si` from its directory.
