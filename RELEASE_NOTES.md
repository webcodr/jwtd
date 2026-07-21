## Homebrew: reverted to a formula

4.0.0 briefly shipped jwtd as a Homebrew **cask**. macOS Gatekeeper blocks casks whose binaries are not notarized, so `jwtd` failed to start with "could not be verified", and casks do not work on Linux at all. 4.0.x now ships as a **formula** again, which fixes both.

**If you installed 4.0.0 via the cask**, switch back once:

```sh
brew uninstall --cask jwtd
brew update
brew install webcodr/tap/jwtd
```

`brew install webcodr/tap/jwtd` works on both macOS and Linux again.
