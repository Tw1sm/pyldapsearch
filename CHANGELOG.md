# Changelog
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
