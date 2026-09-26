# Accounts & Access Tiers

You do not need an account to browse and search the public part of the archive. You only need one if you want to see metadata that has been restricted to registered or vetted users.

## The three tiers

| Tier | How you get it | What it grants |
|---|---|---|
| **Public** | Default for guests and new local accounts | Full public-tier metadata; discovery details for higher-tier datasets |
| **Registered** | Administrator approval after account setup | Full public and registered metadata |
| **Vetted** | Administrator approval after review | Full metadata at every tier |

Creating, verifying, or enrolling an account does not change its tier. Hidden metadata is removed before rendering and is absent from page source.

## Registering for an account

Click **Login** in the navigation, then **Register**. You will be asked for:

- Your email address (used as your login name)
- A display name
- Your institutional affiliation (optional)
- Your country (optional)
- A password

Use 12–200 characters. Passwords are rejected if they match the common-password list or contain your email local part or a display-name word of at least four characters, ignoring case.

Submitting the form shows a generic “check your inbox” page without logging you in. A new account receives queued verification mail; an existing account receives a notice instead. Open the link and press its confirmation button before logging in. Registration may be disabled by the operator.

If **SWITCH edu-ID** login is enabled, use your institutional identity and its required MFA. First sign-in creates a pending account for administrator review, not a session. After approval, sign in again with the same institutional identity; the archive does not require local password/TOTP setup. Matching email addresses never merge institutional and local accounts.

## Verifying your email

Verification links last 24 hours. Open the link and press the confirmation button; opening it alone does not consume it. Request a replacement through **Need a new verification email?** on the login page. Unverified local accounts are normally removed after seven days; the operator can change that period.

## Setting up two-factor authentication

After email verification, log in with email/password to open setup. Use a TOTP-compatible authenticator to scan the QR, save the ten recovery codes separately from that device, then submit a six-digit authenticator code and one recovery code. The confirming recovery code remains usable.

The pending seed lasts ten minutes. Refreshing setup replaces the recovery codes: save the newly displayed set before confirming. Until setup finishes, the session has restricted access. Completion opens the account page; future local logins require password and a fresh authenticator code. Setup does not raise your metadata tier.

## Forgotten passwords

Choose **Forgot password?** and submit your email. Active local accounts receive a queued single-use link valid for 30 minutes. Open it and choose a new password that meets the normal rules and differs from your current one. Completion ends all account sessions; log in again with the new password and authenticator.

The request response does not reveal account eligibility; processing time may differ. Institutional passwords are managed by the identity provider.

## Changing your authenticator

If you still have access to your current authenticator, you can switch to a new
one from your account page. First submit your password and a current code. The
site displays a new QR code; scan it and confirm a code from the new authenticator within five minutes. Your old authenticator remains active until confirmation. Success ends all sessions, so log in again; your saved recovery codes remain valid. Too many invalid confirmations discard only the pending change.

If your authenticator is lost entirely, contact an archive administrator. A
different local administrator must verify your identity and authorize a
30-minute recovery window; the administrator cannot see or generate your saved
codes. Then use **Recover authenticator** on the login page and enter your
email, password, and one saved recovery code. Successful recovery creates a
15-minute setup session. Enrol the replacement and confirm a fresh recovery-code set; the old codes are replaced and all sessions end, requiring a new login.

Each saved code is one-time and allows at most three password attempts. After
three wrong passwords that code can no longer be used, but your other unused
codes remain available. Unknown codes do not lock your account. The page always
uses the same error for an incorrect email, password, or code. A temporary lock
caused by ordinary sign-in failures does not block an administrator-authorized
recovery; successful recovery clears that stale lock state.

Sensitive account actions share a small attempt allowance for the current
session. Successful submissions count as well as rejected ones. If you exhaust
it, only that browser session ends and you must log in again; your account and
sessions on other devices remain active.

## Requesting a higher access tier

After account setup, request **registered** or **vetted** access using the contact address on **Account** or **About**. Include:

- Your name, affiliation, and the email address tied to your account
- A short description of the research project the access is for
- Any institutional ethics approvals or consent documentation that is relevant

Vetted access is granted by an administrator after manual review. There is no automated approval flow.

## Logging out and session expiry

Sessions last up to 8 hours from login by default, after which you are asked to log in again. You can log out manually at any time using the **Logout** link in the navigation. Logging out removes the session from the server, not just the cookie from your browser — so logging out from one device cannot be undone by re-using the cookie elsewhere.

When institutional login is enabled, logout also passes through the archive's Shibboleth service provider, even for local accounts. Wider identity-provider logout depends on the provider. On shared computers, also sign out there and close every browser window.

If your account is deactivated by an administrator, all of its sessions end immediately as part of the deactivation.

## Your account page

**Account** shows your profile, authentication method, tier, join date, and last login. Local users can edit their display name, request an email change after proving their password, and change their authenticator. Institutional names/emails are managed by the institution.

Email changes send confirmation to the new address and a notice to the old address. Confirm within one hour; success changes the verified address and ends all account sessions. Password reset, account deactivation, or administrator unlock can invalidate a pending change.

