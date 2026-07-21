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
    return "scoop";
  }
  if (operatingSystem === "linux") {
    return "linux";
  }
  return "homebrew";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { detectOperatingSystem, installMethodForOperatingSystem };
}

if (typeof document !== "undefined") {
  document.documentElement.classList.add("js");

  const initialize = () => {
    const tabList = document.querySelector("[data-install-tabs]");
    const tabs = Array.from(document.querySelectorAll("[data-install-method]"));
    const panels = Array.from(document.querySelectorAll("[data-install-panel]"));

    const selectTab = (method, moveFocus = false) => {
      for (const tab of tabs) {
        const selected = tab.dataset.installMethod === method;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && moveFocus) {
          tab.focus();
        }
      }

      for (const panel of panels) {
        panel.hidden = panel.dataset.installPanel !== method;
      }
    };

    if (tabList && tabs.length > 0 && panels.length > 0) {
      tabList.setAttribute("role", "tablist");
      for (const tab of tabs) {
        tab.setAttribute("role", "tab");
        tab.setAttribute("aria-controls", `install-${tab.dataset.installMethod}`);
      }
      for (const panel of panels) {
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", `install-tab-${panel.dataset.installPanel}`);
      }

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

      selectTab(installMethodForOperatingSystem(operatingSystem));

      tabs.forEach((tab, index) => {
        tab.addEventListener("click", (event) => {
          event.preventDefault();
          selectTab(tab.dataset.installMethod);
        });

        tab.addEventListener("keydown", (event) => {
          let nextIndex;
          if (event.key === "ArrowRight" || event.key === "ArrowDown") {
            nextIndex = (index + 1) % tabs.length;
          } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
            nextIndex = (index - 1 + tabs.length) % tabs.length;
          } else if (event.key === "Home") {
            nextIndex = 0;
          } else if (event.key === "End") {
            nextIndex = tabs.length - 1;
          } else {
            return;
          }

          event.preventDefault();
          selectTab(tabs[nextIndex].dataset.installMethod, true);
        });
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

        try {
          if (!navigator.clipboard?.writeText) {
            throw new Error("Clipboard API unavailable");
          }
          await navigator.clipboard.writeText(command.textContent.trim());
          feedback.textContent = "Copied.";
        } catch {
          feedback.textContent = "Select the command and copy it manually.";
        }

        feedbackTimers.set(
          button,
          window.setTimeout(() => {
            feedback.textContent = "";
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
