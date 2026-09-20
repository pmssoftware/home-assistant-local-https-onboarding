"use strict";

const state = { platform: "desktop", info: null, messages: {}, locale: "en" };
const detectedHost = window.location.hostname || "homeassistant.local";

function message(key, fallback = key) {
  return state.messages[key] || fallback;
}

function applyTranslations() {
  document.documentElement.lang = state.locale;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = message(element.dataset.i18n, element.textContent);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((element) => {
    element.innerHTML = message(element.dataset.i18nHtml, element.innerHTML);
  });
  document.title = message("pageTitle", document.title);
  if (state.info) {
    document.getElementById("not-after").textContent = formatDate(state.info.not_after);
  }
  selectPlatform(state.platform);
}

async function loadLocale(locale) {
  const response = await fetch(`assets/locales/${encodeURIComponent(locale)}.json`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Language file returned ${response.status}`);
  state.messages = await response.json();
  state.locale = locale;
  localStorage.setItem("onboarding-language", locale);
  applyTranslations();
}

async function prepareLanguages() {
  const response = await fetch("assets/locales/languages.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`Language list returned ${response.status}`);
  const languages = await response.json();
  const select = document.getElementById("language-select");
  for (const language of languages) {
    const option = document.createElement("option");
    option.value = language.code;
    option.textContent = language.name;
    select.append(option);
  }
  const saved = localStorage.getItem("onboarding-language");
  const browser = (navigator.language || "en").toLowerCase().split("-")[0];
  const available = languages.map((language) => language.code);
  const selected = available.includes(saved) ? saved : (available.includes(browser) ? browser : "en");
  select.value = selected;
  await loadLocale(selected);
}

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
  if (platform === "ios") return message("downloadIos", "Download iPhone / iPad profile");
  if (platform === "android") return message("downloadAndroid", "Download Android CA certificate");
  return message("downloadDesktop", "Download public CA certificate");
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
  return new Intl.DateTimeFormat(state.locale, { dateStyle: "long", timeStyle: "short" }).format(parsed);
}

function setConsent(enabled) {
  const install = document.getElementById("install-button");
  install.classList.toggle("disabled", !enabled);
  install.setAttribute("aria-disabled", String(!enabled));
  install.tabIndex = enabled ? 0 : -1;
}

function setQuickMode(enabled) {
  document.getElementById("quick-flow").classList.toggle("hidden", !enabled);
  document.getElementById("certificate-flow").classList.toggle("hidden", enabled);
}

async function start() {
  try {
    await prepareLanguages();
    const response = await fetch(`api/info?host=${encodeURIComponent(detectedHost)}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`Certificate information returned ${response.status}`);
    state.info = await response.json();
    document.getElementById("certificate-name").textContent = state.info.certificate_name;
    document.getElementById("not-after").textContent = formatDate(state.info.not_after);
    document.getElementById("ha-address").textContent = state.info.home_assistant_url;
    document.getElementById("fingerprint").textContent = state.info.fingerprint_sha256;
    document.getElementById("test-link").href = state.info.home_assistant_url;
    document.getElementById("quick-open-link").href = state.info.home_assistant_url;
    document.getElementById("onboarding-address").textContent = state.info.onboarding_url;
    document.getElementById("qr-code").src = `qr.svg?host=${encodeURIComponent(detectedHost)}`;
    selectPlatform(detectPlatform());
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("content").classList.remove("hidden");
  } catch (error) {
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("error").classList.remove("hidden");
    document.getElementById("error-message").textContent = `${message("errorMessage", "The setup information could not be loaded.")} ${error.message}`;
  }
}

document.querySelectorAll("[data-platform]").forEach((button) => {
  button.addEventListener("click", () => selectPlatform(button.dataset.platform));
});

document.getElementById("consent").addEventListener("change", (event) => {
  setConsent(event.target.checked);
});

document.getElementById("quick-mode").addEventListener("change", (event) => {
  setQuickMode(event.target.checked);
});

document.getElementById("language-select").addEventListener("change", async (event) => {
  try {
    await loadLocale(event.target.value);
  } catch (error) {
    document.getElementById("error-message").textContent = error.message;
    document.getElementById("error").classList.remove("hidden");
  }
});

document.getElementById("install-button").addEventListener("click", (event) => {
  if (event.currentTarget.getAttribute("aria-disabled") === "true") event.preventDefault();
});

setConsent(false);
setQuickMode(false);
start();
