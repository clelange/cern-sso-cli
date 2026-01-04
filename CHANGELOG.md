# Changelog

## [0.18.0](https://github.com/clelange/cern-sso-cli/compare/v0.17.1...v0.18.0) (2026-01-04)


### ⚠ BREAKING CHANGES

* --prefer-webauthn flag has been removed
* **cmd:** --prefer-webauthn flag has been removed

### Features

* **auth:** implement 2FA method switching via Try Another Way ([41b18b7](https://github.com/clelange/cern-sso-cli/commit/41b18b7cf543dffccdea16e36bbd13700f608b6e))
* **cmd:** add --use-otp and --use-webauthn flags ([f1db5e1](https://github.com/clelange/cern-sso-cli/commit/f1db5e1b0b69fa216dfaf5dd7487896467246975))
* **cmd:** add 2FA method preference to token command ([449114b](https://github.com/clelange/cern-sso-cli/commit/449114b9ed523ffa4398613cda9fb5cb06893550))
* **parser:** add 2FA method selection page parsing ([3da9b3e](https://github.com/clelange/cern-sso-cli/commit/3da9b3e8f3913c0d3b85bc7e2040772ff3d1fa73))


### Documentation

* document 2FA method preference flags ([a69d8fe](https://github.com/clelange/cern-sso-cli/commit/a69d8feb5432b1e4d9411a86ee7758068cb23834))


### Miscellaneous Chores

* release 0.18.0 ([6409fa4](https://github.com/clelange/cern-sso-cli/commit/6409fa4dd42563bd8889aed0fe8c1a1d0c2eec17))

## [0.17.1](https://github.com/clelange/cern-sso-cli/compare/v0.17.0...v0.17.1) (2026-01-04)


### Bug Fixes

* correct relative URL handling in Kerberos redirect loop ([e6a5b5f](https://github.com/clelange/cern-sso-cli/commit/e6a5b5fbf115779248278caf208bebfd6b40d36e))
* handle rand.Read errors in OIDC state and verifier generation ([f11d705](https://github.com/clelange/cern-sso-cli/commit/f11d7055c0b08a4bfdd697ee31a9af71e8864704))
* remove duplicate defer and correct step numbering in LoginWithKerberos ([48d87e8](https://github.com/clelange/cern-sso-cli/commit/48d87e8d77b701f603b8a40f7ea830f79559bacb))
* replace log.Fatalf with proper error returns in token and device commands ([99facd3](https://github.com/clelange/cern-sso-cli/commit/99facd330fd26b7da361b70e8e08c664f3ef42ec))

## [0.17.0](https://github.com/clelange/cern-sso-cli/compare/v0.16.0...v0.17.0) (2026-01-04)


### ⚠ BREAKING CHANGES

* Requires libfido2 system library for default builds. Build with -tags nowebauthn to disable and avoid dependency.

### Features

* add WebAuthn support ([#43](https://github.com/clelange/cern-sso-cli/issues/43)) ([23f510c](https://github.com/clelange/cern-sso-cli/commit/23f510ce16d51083c293d7e4dbe91e718fe6f4d5))


### Miscellaneous Chores

* release as v0.17.0 ([855d341](https://github.com/clelange/cern-sso-cli/commit/855d341089c1139259ce9c6246cbdab1b010cb27))

## [0.17.0](https://github.com/clelange/cern-sso-cli/compare/v0.16.0...v0.17.0) (2026-01-04)


### Features

* **auth:** add WebAuthn support ([#43](https://github.com/clelange/cern-sso-cli/issues/43)) ([23f510c](https://github.com/clelange/cern-sso-cli/commit/23f510ce16d51083c293d7e4dbe91e718fe6f4d5))

### Fixes

* **auth:** fix WebAuthn assertion flow formatting
* **auth:** fix WebAuthn form parsing for Keycloak HTML structure
* **deps:** update go-libfido2 to unreleased version for OpenSSL 3 support

### Docs

* add WebAuthn support documentation and Dockerfile updates

### CI

* install libfido2 for WebAuthn support on CI runners

## [0.16.0](https://github.com/clelange/cern-sso-cli/compare/v0.15.0...v0.16.0) (2026-01-04)


### Features

* **auth:** add OTP retry mechanism for expired codes and typos ([#40](https://github.com/clelange/cern-sso-cli/issues/40)) ([83ead99](https://github.com/clelange/cern-sso-cli/commit/83ead997ac0b6d798b5ad4aac0d0f07351f574e1))

## [0.15.0](https://github.com/clelange/cern-sso-cli/compare/v0.14.0...v0.15.0) (2026-01-04)


### Features

* **auth:** add OTP command integration for password managers ([#38](https://github.com/clelange/cern-sso-cli/issues/38)) ([5719a80](https://github.com/clelange/cern-sso-cli/commit/5719a80491c7f67ac132d86de769fc11fa569daa))

## [0.14.0](https://github.com/clelange/cern-sso-cli/compare/v0.13.0...v0.14.0) (2026-01-03)


### Features

* **status:** add HTTP verification option for cookie status checks ([#33](https://github.com/clelange/cern-sso-cli/issues/33)) ([deeaf36](https://github.com/clelange/cern-sso-cli/commit/deeaf36106063ba9efe4f86cf6c67e38032c6082))

## [0.13.0](https://github.com/clelange/cern-sso-cli/compare/v0.12.2...v0.13.0) (2026-01-03)


### Features

* add container image with embedded CERN CA certificates ([4a8a401](https://github.com/clelange/cern-sso-cli/commit/4a8a40164947f73e8dd5426d34f94eace2805a58))
* add release-please automation ([62e281c](https://github.com/clelange/cern-sso-cli/commit/62e281c69e3a623c94a13a7dac289358fa82d66a))
