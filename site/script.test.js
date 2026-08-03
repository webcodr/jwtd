

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectOperatingSystem,
  installMethodForOperatingSystem,
  heroCommandForOperatingSystem,
  heroMethodForOperatingSystem,
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
  assert.equal(installMethodForOperatingSystem("macos"), "macos");
  assert.equal(installMethodForOperatingSystem("windows"), "windows");
  assert.equal(installMethodForOperatingSystem("linux"), "linux");
  assert.equal(installMethodForOperatingSystem("unknown"), "macos");
});

test("heroCommandForOperatingSystem selects a working command per platform", () => {
  assert.equal(
    heroCommandForOperatingSystem("windows"),
    "irm https://jwtd.sh/install.ps1 | iex",
  );
  assert.equal(
    heroCommandForOperatingSystem("linux"),
    "curl -fsSL https://jwtd.sh/install.sh | sh",
  );
  assert.equal(heroCommandForOperatingSystem("macos"), "brew install webcodr/tap/jwtd");
  assert.equal(heroCommandForOperatingSystem("unknown"), "brew install webcodr/tap/jwtd");
});

// The hero renders the command as one inline prompt line. A two-line command
// would overflow that line, which is what made the old boxed version look
// broken on Linux and Windows.
test("hero commands stay on a single line", () => {
  for (const operatingSystem of ["macos", "linux", "windows", "unknown"]) {
    assert.ok(
      !heroCommandForOperatingSystem(operatingSystem).includes("\n"),
      `${operatingSystem} hero command must be a single line`,
    );
  }
});

// Nothing in the browser reports the CPU architecture, so a hero command that
// names one hands arm64 visitors a package that cannot run. The install script
// resolves the architecture itself.
test("hero commands never hardcode a CPU architecture", () => {
  for (const operatingSystem of ["macos", "linux", "windows", "unknown"]) {
    const command = heroCommandForOperatingSystem(operatingSystem);
    for (const architecture of ["amd64", "arm64", "x86_64", "aarch64"]) {
      assert.ok(
        !command.includes(architecture),
        `${operatingSystem} hero command must not name ${architecture}: ${command}`,
      );
    }
  }
});

test("heroMethodForOperatingSystem labels the command it accompanies", () => {
  assert.equal(heroMethodForOperatingSystem("macos"), "macOS · Homebrew");
  assert.equal(heroMethodForOperatingSystem("linux"), "Linux · install script");
  assert.equal(heroMethodForOperatingSystem("windows"), "Windows · install script");
  assert.equal(heroMethodForOperatingSystem("unknown"), "macOS · Homebrew");
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
