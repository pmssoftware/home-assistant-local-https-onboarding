# Changelog

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
