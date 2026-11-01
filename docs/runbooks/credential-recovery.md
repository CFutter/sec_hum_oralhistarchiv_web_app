# Credential recovery policy

Email access is a recovery channel; the local password and TOTP authenticator
are login credentials. Saved recovery codes are additional offline credentials.
Do not treat an authenticated browser session or knowledge of an address as
proof of any of these credentials.

| Lost access | Supported path |
| --- | --- |
| Password only | Emailed reset capability plus fresh TOTP; then normal login |
| Email only | Current password plus fresh TOTP to change email; confirm the new address |
| Authenticator only | A different eligible local administrator authorizes recovery; owner supplies current password and an unused, unexhausted saved recovery code |
| Email and password | Administrator verifies identity and stages a new email; owner confirms it, then resets password with a fresh TOTP |
| Email and authenticator | Administrator verifies identity, assists with email and authorizes authenticator recovery; owner still needs current password and a saved recovery code |
| Password and authenticator | No online path is supplied; independently approved operator recovery is required |
| All three, or required recovery codes also lost | Independently approved operator recovery is required |

For combined password/authenticator loss, do not authorize ordinary TOTP
recovery and then send a password reset: authorization removes the old factor,
reset requires a fresh factor, and recovery redemption requires the password.
The sole-administrator break-glass runbook assumes the password is retained and
is not a combined credential-reset procedure.

Combined recovery must be approved under the deployment's identity-verification
and incident procedure, with an independent approver and recorded target,
reason, evidence, executor and timestamps. Do not record passwords, seeds or
recovery codes. This release intentionally supplies no generic SQL password
replacement recipe or new admin bypass. If the deployment has not approved a
combined procedure, escalate to its security owner rather than weakening the
normal credential checks or creating a replacement account with copied access.

An active local account still awaiting initial authenticator enrollment also
cannot complete TOTP-protected password reset. A user retaining the password
can log in and finish enrollment; otherwise approved operator assistance is
required. Institutional account recovery stays with its identity provider.

Every normal successful password change/reset revokes sessions and pending
authentication capabilities and queues a notification atomically. Current TOTP
and active recovery codes remain. Reset proof attempts are bounded per account
and replacement emails do not replenish the current 30-minute window.
