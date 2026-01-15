# Changelog

## [0.24.0](https://github.com/clelange/cern-sso-cli/compare/v0.23.0...v0.24.0) (2026-01-15)


### Features

* **auth:** add keytab support and improve kerberos auth ([78e913c](https://github.com/clelange/cern-sso-cli/commit/78e913cacd873a1dcfd72ac7cd4eed69ac3171b6)), closes [#71](https://github.com/clelange/cern-sso-cli/issues/71)

## [0.23.0](https://github.com/clelange/cern-sso-cli/compare/v0.22.1...v0.23.0) (2026-01-08)


### Features

* add self-update command ([0c4f5b2](https://github.com/clelange/cern-sso-cli/commit/0c4f5b2146003aa8e0fabdbc42c6200cbfcbe843))

## [0.22.1](https://github.com/clelange/cern-sso-cli/compare/v0.22.0...v0.22.1) (2026-01-06)


### Bug Fixes

* **webauthn:** redirect user messages to stderr and add SIGTERM handling ([a1f4c81](https://github.com/clelange/cern-sso-cli/commit/a1f4c81585183d158ebccf50afaed969d7293929))

## [0.22.0](https://github.com/clelange/cern-sso-cli/compare/v0.21.0...v0.22.0) (2026-01-06)


### Features

* **auth:** add interrupt signal handling for WebAuthn assertion ([d2102c1](https://github.com/clelange/cern-sso-cli/commit/d2102c15bf3e3b3da7f702a84c3f957aeb92f2b6))

## [0.21.0](https://github.com/clelange/cern-sso-cli/compare/v0.20.0...v0.21.0) (2026-01-05)


### Features

* add --json output flag to cookie, token, and device commands ([#65](https://github.com/clelange/cern-sso-cli/issues/65)) ([94542f2](https://github.com/clelange/cern-sso-cli/commit/94542f232612861a10c76e839fbd41d64781b4ce))

## [0.20.0](https://github.com/clelange/cern-sso-cli/compare/v0.19.1...v0.20.0) (2026-01-04)


### Features

* **install:** add curl-able installation script ([b3a4977](https://github.com/clelange/cern-sso-cli/commit/b3a49772fd4b5a0cae1bf1a1d9026e5e314f314e)), closes [#59](https://github.com/clelange/cern-sso-cli/issues/59)

## [0.19.1](https://github.com/clelange/cern-sso-cli/compare/v0.19.0...v0.19.1) (2026-01-04)


### Bug Fixes

* **release:** add GH_TOKEN for gh release download command ([67c51f9](https://github.com/clelange/cern-sso-cli/commit/67c51f96816cb1543bdc8776ff10aaa37be0ec3a))

## [0.19.0](https://github.com/clelange/cern-sso-cli/compare/v0.18.0...v0.19.0) (2026-01-04)


### Features

* **release:** add checksums for release binaries ([5b2dbf5](https://github.com/clelange/cern-sso-cli/commit/5b2dbf55cb17e8b1a543f63a494f69cec460b999))


### Bug Fixes

* **release:** correct macOS runners for WebAuthn builds ([54876a2](https://github.com/clelange/cern-sso-cli/commit/54876a2fd9c9d6f2c98f2ffef34cdf9ed72afb20))

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
