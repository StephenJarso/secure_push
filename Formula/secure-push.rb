# typed: false
# frozen_string_literal: true

class SecurePush < Formula
  desc "Security scanner for your codebase"
  homepage "https://github.com/secure-push/secure-push"
  version "0.1.0"
  license "MIT"

  depends_on "go" => :build

  on_macos do
    on_intel do
      url "https://github.com/secure-push/secure-push/releases/download/v0.1.0/secure-push_0.1.0_darwin_amd64.tar.gz"
      sha256 "PLACEHOLDER"
    end
    on_arm do
      url "https://github.com/secure-push/secure-push/releases/download/v0.1.0/secure-push_0.1.0_darwin_arm64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/secure-push/secure-push/releases/download/v0.1.0/secure-push_0.1.0_linux_amd64.tar.gz"
      sha256 "PLACEHOLDER"
    end
    on_arm do
      url "https://github.com/secure-push/secure-push/releases/download/v0.1.0/secure-push_0.1.0_linux_arm64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "secure-push"
  end

  test do
    assert_match "secure-push version", shell_output("#{bin}/secure-push version")
  end
end