## Highlights

### WinGet (Windows)

jwtd is now installable with the built-in Windows Package Manager:

```
winget install WebCodr.jwtd
```

The manifest installs the same signed release binary as every other channel, packaged as a portable zip whose hashes are taken from the release's signed `checksums.txt`. Windows releases now ship an additional `.zip` archive alongside the existing `.tar.gz`; its `jwtd.exe` is byte-for-byte the same binary. Scoop, Homebrew, AUR, Fedora COPR, and Nix are unchanged.
