## Breaking: Homebrew is now a cask (macOS only)

jwtd's Homebrew package has moved from a formula to a **cask**, which Homebrew supports on macOS only.

**Existing macOS users** installed via the formula must switch once:

```sh
brew uninstall jwtd
brew update
brew install --cask webcodr/tap/jwtd
```

`brew upgrade jwtd` will **not** migrate you automatically — the formula has been removed from the tap.

**Linux users:** Homebrew casks do not work on Linux, so `brew install webcodr/tap/jwtd` is no longer available there. Install one of the new Linux packages instead:

```sh
sudo dpkg -i jwtd-linux-amd64.deb   # Debian/Ubuntu
sudo rpm -i  jwtd-linux-amd64.rpm   # Fedora/RHEL/openSUSE
```

or download a release archive below.
