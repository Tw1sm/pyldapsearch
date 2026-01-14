# Changelog
## [v0.1.9] - 1/6/2026
### Added
- Support for parsing dnsRecord attributes ([#2](https://github.com/Tw1sm/pyldapsearch/pull/7))

## [v0.1.8] - 12/1/2025
### Changed
- Switch ldap3 dependency from [https://github.com/ly4k/ldap3](https://github.com/ly4k/ldap3) to `ldap3-bleeding-edge`

## [v0.1.7] - 3/1/2025
### Added
- `setuptools` dependency to fix import error

## [v0.1.6] - 2/8/2025
## Fixed
- Properly encode `securityIdentifer` attribute (for `trusteddomain` objects)

## [v0.1.5] - 6/2/2024
### Fixed
- Fixed bug where `cACertificate` property would fail to base64 encode if more than 1 cert was present (attr formatted as list)

## [v0.1.4] - 5/25/2024
### Added
- Merge in [#2](https://github.com/Tw1sm/pyldapsearch/pull/2) (Palu08)
    - `-scope` flag to let the user chose between "BASE","LEVEL" and "SUBTREE" values
    - `-output` flag to let the user chose a supplementary output file
- `pycrytodome` dependency

## [v0.1.3] - 12/7/2023
### Added
- Support for LDAPS channel binding

### Changed
- `ldap3` dependency is now installed from [https://github.com/ly4k/ldap3](https://github.com/ly4k/ldap3) until this [PR](https://github.com/cannatag/ldap3/pull/1087) is merged into the main `ldap3` library

## [v0.1.2] - 9/26/2022
### Fixed
- LDAPInvalidFilterError is now caught

### Changed
- Improved help menus
- Updated dependencies

## [v0.1.1] - 6/22/2022
### Changed
- Updated dependencies

## [v0.1.0] - 5/20/2022
### Added
- `-no-smb` to allow operator choice over whether an SMB connection is made to the DC to determine its hostname. If used, `-dc-ip` requires the DCs hostname to work
### Fixed
- Duplicate/erroneous logging statements

## [v0.0.1] - 5/9/2022
### Added
- Prepped for initial release and PyPI package
