# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.6](https://github.com/maidsafe/safeup/compare/v0.3.5...v0.3.6) - 2023-07-07

### Added
- allow m1 mac installs

## [0.3.5](https://github.com/maidsafe/safeup/compare/v0.3.4...v0.3.5) - 2023-06-21

### Added
- support armv7 architecture

### Fixed
- use `-Force` option on zip extraction

## [0.3.4](https://github.com/maidsafe/safeup/compare/v0.3.3...v0.3.4) - 2023-06-19

### Other
- alt mechanism for downloading install script
- use zip rather than tar archive

## [0.3.3](https://github.com/maidsafe/safeup/compare/v0.3.2...v0.3.3) - 2023-06-19

### Fixed
- allow arm macs to install x86 bins, as those will work

## [0.3.2](https://github.com/maidsafe/safeup/compare/v0.3.1...v0.3.2) - 2023-06-17

### Added
- set user path variable for windows

## [0.3.1](https://github.com/maidsafe/safeup/compare/v0.3.0...v0.3.1) - 2023-06-16

### Other
- fix bad script references

## [0.3.0](https://github.com/maidsafe/safeup/compare/v0.2.1...v0.3.0) - 2023-06-16

### Added
- do not install client by default

## [0.2.1](https://github.com/maidsafe/safeup/compare/v0.2.0...v0.2.1) - 2023-06-16

### Added
- use banners for install process
- provide powershell install script
- provide unix-based install script

### Other
- provide installation instructions

## [0.2.0](https://github.com/maidsafe/safeup/compare/v0.1.2...v0.2.0) - 2023-06-16

### Added
- use `~/.local/bin` as install location

### Other
- provide build job

## [0.1.2](https://github.com/maidsafe/safeup/compare/v0.1.1...v0.1.2) - 2023-06-15

### Other
- ignore directories used in release process

## [0.1.1](https://github.com/maidsafe/safeup/compare/v0.1.0...v0.1.1) - 2023-06-14

### Other
- improve cli documentation

## [0.1.0](https://github.com/jacderida/safeup/releases/tag/v0.1.0) - 2023-06-14

### Added
- full installations of binaries on windows
- provide `testnet` subcommand
- provide node command
- support installing specific versions
- modify shell profile for safe on path
- provide `client` command

### Other
- implement release process
- accommodate multiple github releases
- integration test for windows installations
- use config directory for safeup config
- vary location of shell profile
- add settings file to keep track of installs
- run some integration tests
- updates for dealing with new release format
- apply license headers and style recommendations
- provide initial command info
- provide standard workflows
- Initial commit
