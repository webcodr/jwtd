class Jwtd < Formula
  desc "Decode and pretty-print JSON Web Tokens with syntax highlighting"
  homepage "https://github.com/webcodr/jwtd"
  version "VERSION"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/webcodr/jwtd/releases/download/vVERSION/jwtd-darwin-arm64.tar.gz"
      sha256 "SHA256_DARWIN_ARM64"
    else
      url "https://github.com/webcodr/jwtd/releases/download/vVERSION/jwtd-darwin-amd64.tar.gz"
      sha256 "SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/webcodr/jwtd/releases/download/vVERSION/jwtd-linux-arm64.tar.gz"
      sha256 "SHA256_LINUX_ARM64"
    else
      url "https://github.com/webcodr/jwtd/releases/download/vVERSION/jwtd-linux-amd64.tar.gz"
      sha256 "SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install "jwtd"
  end

  test do
    assert_match "jwtd", shell_output("#{bin}/jwtd --help")
  end
end
