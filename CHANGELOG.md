# Changelog

This file records reviewed changes from the current development checkpoint.
It does not reconstruct earlier release dates or assert that a public release
has already been published.

## Unreleased

### Added

- Project licensing and third-party notice files, with distribution metadata
  and release packaging for the applicable notices.
- Contribution, security-reporting and citation guidance, plus issue and pull
  request templates.
- Before-staging status/evidence records and a site-reference policy and gate.

### Changed

- Institutional examples and synthetic fixtures use neutral values while
  public protocol references and compatibility rejection guards are retained.

### Fixed

- Login content now stays inside its authentication layout section, including
  success notices, failed submissions and the optional institutional entry.
- About, account and user-guide access descriptions account for field restrictions and
  administrator-hidden records without promising full metadata from a record's
  tier alone.
- Shared OAI fixture documentation names its current canonical role; a redundant
  timestamp-specific database ignore entry is removed under the existing rule.
- The roadmap recognizes implemented TOTP success notices, and remaining OAI
  test cross-references point to the current parser and rebuild test modules.

Repository templates and green automated checks do not establish execution of
staging, production, registration, federation, source or publication gates.

The development package version remains `0.1.0`; this entry does not create a
release tag or announce support for that version.
