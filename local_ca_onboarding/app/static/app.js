"use strict";

const state = { platform: "desktop", info: null };
const detectedHost = window.location.hostname || "homeassistant.local";

function detectPlatform() {
  const ua = navigator.userAgent || "";
  if (/iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)) {
    return "ios";
  }
  if (/Android/i.test(ua)) return "android";
  return "desktop";
}

function downloadFor(platform) {
  if (platform === "ios") return "download/home-assistant-local-https.mobileconfig";
  if (platform === "android") return "download/home-assistant-local-ca.cer";
  return "download/home-assistant-local-ca.crt";
}

function buttonText(platform) {
  if (platform === "ios") return "Download iPhone / iPad profile";
  if (platform === "android") return "Download Android CA certificate";
  return "Download public CA certificate";
}

function selectPlatform(platform) {
  state.platform = platform;
  document.querySelectorAll("[data-platform]").forEach((button) => {
    const active = button.dataset.platform === platform;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll("[data-instructions]").forEach((panel) => {
    panel.hidden = panel.dataset.instructions !== platform;
  });
  const install = document.getElementById("install-button");
  install.textContent = buttonText(platform);
  const download = downloadFor(platform);
  install.href = platform === "ios"
    ? `${download}?host=${encodeURIComponent(detectedHost)}`
    : download;
}

function formatDate(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "long", timeStyle: "short" }).format(parsed);
}

function setConsent(enabled) {
  const install = document.getElementById("install-button");
  install.classList.toggle("disabled", !enabled);
  install.setAttribute("aria-disabled", String(!enabled));
  install.tabIndex = enabled ? 0 : -1;
}

async function start() {
  try {
    const response = await fetch(`api/info?host=${encodeURIComponent(detectedHost)}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`Certificate information returned ${response.status}`);
    state.info = await response.json();
    document.getElementById("certificate-name").textContent = state.info.certificate_name;
    document.getElementById("not-after").textContent = formatDate(state.info.not_after);
    document.getElementById("ha-address").textContent = state.info.home_assistant_url;
    document.getElementById("fingerprint").textContent = state.info.fingerprint_sha256;
    document.getElementById("test-link").href = state.info.home_assistant_url;
    document.getElementById("onboarding-address").textContent = state.info.onboarding_url;
    document.getElementById("qr-code").src = `qr.svg?host=${encodeURIComponent(detectedHost)}`;
    selectPlatform(detectPlatform());
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("content").classList.remove("hidden");
  } catch (error) {
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("error").classList.remove("hidden");
    document.getElementById("error-message").textContent = error.message;
  }
}

document.querySelectorAll("[data-platform]").forEach((button) => {
  button.addEventListener("click", () => selectPlatform(button.dataset.platform));
});

document.getElementById("consent").addEventListener("change", (event) => {
  setConsent(event.target.checked);
});

document.getElementById("install-button").addEventListener("click", (event) => {
  if (event.currentTarget.getAttribute("aria-disabled") === "true") event.preventDefault();
});

setConsent(false);
start();
