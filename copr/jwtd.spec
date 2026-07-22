%global debug_package %{nil}

Name:           jwtd
Version:        VERSION
Release:        1%{?dist}
Summary:        Decode and pretty-print JSON Web Tokens with syntax highlighting

License:        MIT
URL:            https://github.com/webcodr/jwtd
ExclusiveArch:  x86_64 aarch64

# Prebuilt, signed upstream release binaries; nothing is compiled here. The
# release archives use version-free names, so the Source URLs pin the version
# in the path.
Source0:        https://github.com/webcodr/jwtd/releases/download/v%{version}/jwtd-linux-amd64.tar.gz
Source1:        https://github.com/webcodr/jwtd/releases/download/v%{version}/jwtd-linux-arm64.tar.gz
Source2:        LICENSE

%description
jwtd decodes and pretty-prints JSON Web Tokens (JWT), JSON Web Signatures
(JWS), and JSON Web Encryption (JWE) tokens with syntax-highlighted output.
It can verify JWS signatures and decrypt JWE payloads when given a key.

%prep

%build

%install
%ifarch x86_64
tar -xzf %{SOURCE0}
%endif
%ifarch aarch64
tar -xzf %{SOURCE1}
%endif
install -Dpm0755 jwtd %{buildroot}%{_bindir}/jwtd
install -Dpm0644 %{SOURCE2} %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license %{_licensedir}/%{name}/LICENSE
%{_bindir}/jwtd

%changelog
* DATE David Henning <dev@webcodr.io> - VERSION-1
- Automated release of jwtd VERSION
