"use strict";

function classifyPlatform(value) {
  const normalized = String(value || "").toLowerCase();

  if (/mac|iphone|ipad|ipod/.test(normalized)) {
    return "macos";
  }
  if (/win/.test(normalized)) {
    return "windows";
  }
  if (/linux|x11/.test(normalized)) {
    return "linux";
  }
  return "unknown";
}

function detectOperatingSystem(userAgentDataPlatform, platform, userAgent) {
  for (const candidate of [userAgentDataPlatform, platform, userAgent]) {
    const detected = classifyPlatform(candidate);
    if (detected !== "unknown") {
      return detected;
    }
  }
  return "unknown";
}

function installMethodForOperatingSystem(operatingSystem) {
  if (operatingSystem === "windows") {
    return "windows";
  }
  if (operatingSystem === "linux") {
    return "linux";
  }
  return "macos";
}

// The hero renders these as a single inline prompt line, so every one of them
// must stay on one line. They must also not name a CPU architecture: nothing in
// the browser reports it, so the Linux entry deliberately uses the install
// script, which detects the architecture itself.
function heroCommandForOperatingSystem(operatingSystem) {
  if (operatingSystem === "windows") {
    return "irm https://jwtd.sh/install.ps1 | iex";
  }
  if (operatingSystem === "linux") {
    return "curl -fsSL https://jwtd.sh/install.sh | sh";
  }
  return "brew install webcodr/tap/jwtd";
}

// Names the method the command above uses, so the hero line is not an
// unlabelled command the way the boxed version was.
function heroMethodForOperatingSystem(operatingSystem) {
  if (operatingSystem === "windows") {
    return "Windows · install script";
  }
  if (operatingSystem === "linux") {
    return "Linux · install script";
  }
  return "macOS · Homebrew";
}

function heroCopyLabelForOperatingSystem(operatingSystem) {
  if (operatingSystem === "windows") {
    return "Copy Windows install script command";
  }
  if (operatingSystem === "linux") {
    return "Copy Linux install script command";
  }
  return "Copy macOS Homebrew install command";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    detectOperatingSystem,
    installMethodForOperatingSystem,
    heroCommandForOperatingSystem,
    heroMethodForOperatingSystem,
    heroCopyLabelForOperatingSystem,
  };
}

if (typeof document !== "undefined") {
  document.documentElement.classList.add("js");

  const setupHorizontalTabs = ({
    tabList,
    tabs,
    panels,
    getTabKey,
    getPanelKey,
    panelIdPrefix,
    tabIdPrefix,
    initialKey,
    onSelect,
  }) => {
    if (!tabList || tabs.length === 0 || panels.length === 0) {
      return null;
    }

    const selectTab = (key, moveFocus = false) => {
      for (const tab of tabs) {
        const selected = getTabKey(tab) === key;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && moveFocus) {
          tab.focus();
        }
      }

      for (const panel of panels) {
        panel.hidden = getPanelKey(panel) !== key;
      }
    };

    tabList.setAttribute("role", "tablist");
    for (const tab of tabs) {
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-controls", `${panelIdPrefix}${getTabKey(tab)}`);
    }
    for (const panel of panels) {
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", `${tabIdPrefix}${getPanelKey(panel)}`);
      panel.tabIndex = 0;
    }

    selectTab(initialKey);

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", (event) => {
        event.preventDefault();
        const key = getTabKey(tab);
        selectTab(key);
        onSelect?.(key);
      });

      // Horizontal tablists follow WAI-ARIA APG: Left/Right/Home/End switch
      // tabs while Up/Down remain free to scroll the page.
      tab.addEventListener("keydown", (event) => {
        let nextIndex;
        if (event.key === "ArrowRight") {
          nextIndex = (index + 1) % tabs.length;
        } else if (event.key === "ArrowLeft") {
          nextIndex = (index - 1 + tabs.length) % tabs.length;
        } else if (event.key === "Home") {
          nextIndex = 0;
        } else if (event.key === "End") {
          nextIndex = tabs.length - 1;
        } else {
          return;
        }

        event.preventDefault();
        const key = getTabKey(tabs[nextIndex]);
        selectTab(key, true);
        onSelect?.(key);
      });
    });

    return selectTab;
  };

  const initialize = () => {
    let operatingSystem = "unknown";
    try {
      operatingSystem = detectOperatingSystem(
        navigator.userAgentData?.platform || "",
        navigator.platform || "",
        navigator.userAgent || "",
      );
    } catch {
      operatingSystem = "unknown";
    }

    const heroCommand = document.getElementById("hero-install-command");
    if (heroCommand) {
      heroCommand.textContent = heroCommandForOperatingSystem(operatingSystem);
    }

    const heroMethod = document.getElementById("hero-install-method");
    if (heroMethod) {
      heroMethod.textContent = heroMethodForOperatingSystem(operatingSystem);
    }

    const heroCopyButton = document.querySelector(
      '[data-copy-target="hero-install-command"]',
    );
    if (heroCopyButton) {
      heroCopyButton.setAttribute(
        "aria-label",
        heroCopyLabelForOperatingSystem(operatingSystem),
      );
    }

    const specimenTabList = document.querySelector("[data-specimen-tabs]");
    const specimenTabs = Array.from(
      document.querySelectorAll("[data-specimen-tab]"),
    );
    const specimenPanels = Array.from(
      document.querySelectorAll("[data-specimen-panel]"),
    );
    setupHorizontalTabs({
      tabList: specimenTabList,
      tabs: specimenTabs,
      panels: specimenPanels,
      getTabKey: (tab) => tab.dataset.specimenTab,
      getPanelKey: (panel) => panel.dataset.specimenPanel,
      panelIdPrefix: "specimen-",
      tabIdPrefix: "specimen-tab-",
      initialKey: "decode",
    });

    const tabList = document.querySelector("[data-install-tabs]");
    const tabs = Array.from(document.querySelectorAll("[data-install-method]"));
    const panels = Array.from(document.querySelectorAll("[data-install-panel]"));

    const methodForHash = (hash) => {
      const match = /^#install-([a-z]+)$/.exec(hash || "");
      if (match && tabs.some((tab) => tab.dataset.installMethod === match[1])) {
        return match[1];
      }
      return null;
    };

    const rememberSelection = (method) => {
      window.history.replaceState(null, "", `#install-${method}`);
    };

    const selectInstallTab = setupHorizontalTabs({
      tabList,
      tabs,
      panels,
      getTabKey: (tab) => tab.dataset.installMethod,
      getPanelKey: (panel) => panel.dataset.installPanel,
      panelIdPrefix: "install-",
      tabIdPrefix: "install-tab-",
      initialKey:
        methodForHash(window.location.hash) ||
        installMethodForOperatingSystem(operatingSystem),
      onSelect: rememberSelection,
    });

    if (selectInstallTab) {
      window.addEventListener("hashchange", () => {
        const method = methodForHash(window.location.hash);
        if (method) {
          selectInstallTab(method);
        }
      });
    }

    const feedbackTimers = new WeakMap();
    for (const button of document.querySelectorAll("[data-copy-target]")) {
      button.addEventListener("click", async () => {
        const command = document.getElementById(button.dataset.copyTarget);
        const feedback = button.parentElement.querySelector("[data-copy-feedback]");
        if (!command || !feedback) {
          return;
        }

        const previousTimer = feedbackTimers.get(button);
        if (previousTimer) {
          window.clearTimeout(previousTimer);
        }

        // Clearing before reassigning lets aria-live re-announce consecutive
        // clicks within the 3-second feedback window.
        feedback.textContent = "";
        delete button.dataset.copied;

        let message;
        let copied = false;
        try {
          if (!navigator.clipboard?.writeText) {
            throw new Error("Clipboard API unavailable");
          }
          await navigator.clipboard.writeText(command.textContent.trim());
          message = "Copied.";
          copied = true;
        } catch {
          message = "Select the command and copy it manually.";
        }

        window.setTimeout(() => {
          feedback.textContent = message;
          if (copied) {
            button.dataset.copied = "true";
          }
        }, 0);

        feedbackTimers.set(
          button,
          window.setTimeout(() => {
            feedback.textContent = "";
            delete button.dataset.copied;
          }, 3000),
        );
      });
    }

    const navToggle = document.querySelector("[data-nav-toggle]");
    const navigation = document.getElementById("primary-navigation");
    if (navToggle && navigation) {
      const closeNavigation = (restoreFocus = false) => {
        navToggle.setAttribute("aria-expanded", "false");
        navigation.dataset.open = "false";
        if (restoreFocus) {
          navToggle.focus();
        }
      };

      navToggle.addEventListener("click", () => {
        const open = navToggle.getAttribute("aria-expanded") !== "true";
        navToggle.setAttribute("aria-expanded", String(open));
        navigation.dataset.open = String(open);
      });

      navigation.addEventListener("click", (event) => {
        if (event.target.closest("a")) {
          closeNavigation();
        }
      });

      document.addEventListener("click", (event) => {
        if (
          navToggle.getAttribute("aria-expanded") === "true" &&
          !event.target.closest("#primary-navigation") &&
          !event.target.closest("[data-nav-toggle]")
        ) {
          closeNavigation();
        }
      });

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && navToggle.getAttribute("aria-expanded") === "true") {
          closeNavigation(true);
        }
      });
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
}
