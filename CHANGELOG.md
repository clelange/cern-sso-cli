# Changelog

## [1.0.0](https://github.com/clelange/cern-sso-cli/compare/v0.16.0...v1.0.0) (2026-01-04)


### ⚠ BREAKING CHANGES

* Requires libfido2 system library for default builds. Build with -tags nowebauthn to disable and avoid dependency.

### Features

* add WebAuthn support ([#43](https://github.com/clelange/cern-sso-cli/issues/43)) ([23f510c](https://github.com/clelange/cern-sso-cli/commit/23f510ce16d51083c293d7e4dbe91e718fe6f4d5))

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
