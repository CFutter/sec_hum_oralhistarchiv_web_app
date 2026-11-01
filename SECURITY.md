# Security policy

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** option for this repository if private
vulnerability reporting is enabled. Otherwise, ask a maintainer for the approved
private reporting channel before sharing sensitive details. Ordinary bugs belong
in the [bug report form](.github/ISSUE_TEMPLATE/bug_report.yml).

Do not open a public issue containing an exploit, credentials, session or action
codes, personal information, restricted catalogue metadata or real source data.
Use a minimal synthetic example. Privately include the affected source commit
or release, configuration relevant to the boundary, reproduction steps, observed
impact and any suggested repair. Remove secrets from logs and captures before
sharing them through the agreed channel.

Testing must use systems and data for which you have authorization. This policy
does not grant permission to test a deployed service or its upstream sources.
For an active deployment incident, use that deployment's approved incident
response and containment procedure.

## Development and support status

The repository currently uses development version `0.1.0`. This policy does not
announce a supported public release, an incident-response service or guaranteed
response times. Deployments must pin reviewed artifacts and follow their own
accepted operational procedures.

Before publication, maintainers must configure and verify a private reporting
route, assign responsibility and publish the supported-version and response
policy. These adoption decisions remain open; adding this file does not confirm
that GitHub private reporting or another contact channel is enabled.

## Coordinated handling

Keep the initial report private while maintainers assess it and coordinate any
repair and release. Agree disclosure timing through the private channel. Avoid
including sensitive source records or working credentials in a patch or test;
regressions should demonstrate the boundary with synthetic data.

See [contributing](CONTRIBUTING.md) and
[the incident-response template](docs/compliance/incident-response.md).
