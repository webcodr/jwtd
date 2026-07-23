

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectOperatingSystem,
  installMethodForOperatingSystem,
  heroCommandForOperatingSystem,
} = require("./script.js");

test("detectOperatingSystem classifies supported operating systems", () => {
  const cases = [
    ["macOS", "", "", "macos"],
    ["", "MacIntel", "", "macos"],
    ["", "", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"],
    ["Windows", "", "", "windows"],
    ["", "Win32", "", "windows"],
    ["", "", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"],
    ["Linux", "", "", "linux"],
    ["", "Linux x86_64", "", "linux"],
    ["", "", "Mozilla/5.0 (X11; Linux x86_64)", "linux"],
  ];

  for (const [userAgentDataPlatform, platform, userAgent, expected] of cases) {
    assert.equal(
      detectOperatingSystem(userAgentDataPlatform, platform, userAgent),
      expected,
    );
  }
});

test("detectOperatingSystem returns unknown when no platform matches", () => {
  assert.equal(detectOperatingSystem("", "", ""), "unknown");
  assert.equal(detectOperatingSystem("Plan 9", "Unknown", "custom-client"), "unknown");
});

test("installMethodForOperatingSystem selects the approved default", () => {
  assert.equal(installMethodForOperatingSystem("macos"), "homebrew");
  assert.equal(installMethodForOperatingSystem("windows"), "scoop");
  assert.equal(installMethodForOperatingSystem("linux"), "linux");
  assert.equal(installMethodForOperatingSystem("unknown"), "homebrew");
});

test("heroCommandForOperatingSystem selects a working command per platform", () => {
  assert.equal(
    heroCommandForOperatingSystem("windows"),
    "scoop bucket add webcodr https://github.com/webcodr/scoop-bucket\nscoop install jwtd",
  );
  assert.equal(
    heroCommandForOperatingSystem("linux"),
    "curl -fLO https://github.com/webcodr/jwtd/releases/latest/download/jwtd-linux-amd64.deb\nsudo dpkg -i jwtd-linux-amd64.deb",
  );
  assert.equal(heroCommandForOperatingSystem("macos"), "brew install webcodr/tap/jwtd");
  assert.equal(heroCommandForOperatingSystem("unknown"), "brew install webcodr/tap/jwtd");
});

test("detectOperatingSystem honors platform source priority", () => {
  assert.equal(
    detectOperatingSystem("Windows", "MacIntel", "Mozilla/5.0 (X11; Linux x86_64)"),
    "windows",
  );
  assert.equal(
    detectOperatingSystem("", "MacIntel", "Mozilla/5.0 (Windows NT 10.0)"),
    "macos",
  );
});
