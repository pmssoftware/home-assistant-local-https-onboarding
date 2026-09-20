# Changelog

## 0.2.6

- Fix formatted German translations in the safety notice, quick-mode warning,
  and all device instruction blocks.
- Stop caching UI scripts and styles so app updates appear without a forced
  browser refresh.
- Match Home Assistant's default flat background colors in light and dark mode.

## 0.2.5

- Add complete German and English onboarding UI translations.
- Detect the browser language automatically and add a language selector.
- Store translations in separate JSON locale files with a small language
  registry so contributors can add more languages without changing the layout.

## 0.2.4

- Add an optional browser-only quick mode that skips CA installation and opens
  Home Assistant directly so the browser can offer its own certificate exception.
- Clearly explain that an exception is limited to that browser and is not the
  same as installing and trusting the CA.

## 0.2.3

- Install the OpenSSL runtime required for certificate discovery and validation.
- Add a CI smoke test that starts the real container with a mounted CA and checks
  its health endpoint.

## 0.2.2

- Inspect every certificate in full-chain PEM files instead of only the first.
- Deduplicate the same root CA when it appears both separately and in a chain.
- Log scanned certificate filenames and rejection reasons for easier diagnosis.

## 0.2.1

- Add explicit empty defaults for every automatic option so Supervisor never
  reports a missing required option on an existing installation.

## 0.2.0

- Remove all required configuration fields for first start.
- Automatically discover the public self-signed CA certificate in `/ssl`.
- Automatically derive the Home Assistant address from each browser request.
- Keep optional advanced overrides for unusual installations.

## 0.1.0

- Initial consent-based onboarding flow.
- iOS/iPadOS configuration profile download.
- Android DER certificate download.
- Desktop certificate download and browser-specific instructions.
- QR code, certificate metadata, and trusted Home Assistant launch link.
