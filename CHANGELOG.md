# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][1]. and this project adheres
to [Semantic Versioning][2].

[1]: https://keepachangelog.com/en/1.1.0/
[2]: https://semver.org/spec/v2.0.0.html

## [1.0.1](https://github.com/mlibrary/puppet-fwknop/tree/v1.0.1) - 2024-08-23

### Added

- Reference documentation is generated when releasing to puppet forge.

## [1.0.0](https://github.com/mlibrary/puppet-fwknop/tree/v1.0.0) - 2024-08-23

### Added

- Complete reference documentation.
- `package_manage` and `service_manage` parameters so this module's
  management of the package and service are optional.

## [0.1.0](https://github.com/mlibrary/puppet-fwknop/tree/v0.1.0) - 2024-08-22

### Added

- `fwknop` class which manages `/etc/fwknop/fwknopd.conf` and
  `/etc/fwknop/access.conf`
- `fwknop::access` defined type which adds stanzas to
  `/etc/fwknop/access.conf`
- Very little documentation.
- CI automation for running tests and releasing with puppet forge.
