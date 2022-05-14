# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.7] - 2022-05-14
### Changed
- Collapsed k8s package into the auth package to make it less annoying to set up authentication
- All requests to the Vault API are now sent with a `x-vault-request` header to support the Vault Agent
- Improved package documentation

## [0.0.6] - 2022-05-14
### Changed
- Tests use fakes instead of generated mocks

## [0.0.5] - 2022-05-13
### Changed
- DB GenerateCredentials return Credentials struct instead of a pointer

## [0.0.4] - 2022-05-13
### Added
- Lease information is now available on Database credentials so that you know when the secret expires

## [0.0.3] - 2022-05-05
### Changed
- vaultx client uses functions for nested client gateways instead of struct fields for improved testability

### Fixed
- Flaky tests
- Formatting check in CI to check imports

## [0.0.2] - 2022-05-04
### Added
- README badges

## [0.0.1] - 2022-05-04
### Added
- Generated mocks in order for the package to be usable

## [0.0.0] - 2022-05-04
### Added
- Initial release
