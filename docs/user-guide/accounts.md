# Accounts & Access Tiers

You do not need an account to browse and search the public part of the archive.
An account is needed to access metadata restricted to registered or vetted users.

## The three tiers

| Tier | How you get it | What it grants |
|---|---|---|
| **Public** | Default for guests and new local accounts | Basic catalogue details and metadata fields requiring public access |
| **Registered** | Administrator approval after account setup | Metadata fields requiring public or registered access |
| **Vetted** | Administrator approval after review | Metadata fields requiring public, registered or vetted access in listed datasets |

The dataset's visibility tier sets a minimum for protected metadata. Individual
fields and their source can require a higher tier; the strictest requirement
applies to each field. A public-tier dataset can therefore still contain
restricted fields. Full metadata access requires permission for every field;
resource links also require that full access and a usable link. The originating
repository separately controls access to recordings and other materials.

Creating, verifying, or enrolling an account does not raise its tier.
Restricted metadata is omitted from the response and is absent from page source.
Datasets hidden by an administrator are excluded from the catalogue at every tier.

## Registering for an account

Click **Login** in the navigation, then **Register**, and enter your email address.
This first form asks only for email. You choose your password and profile after
opening the emailed setup link.

Submitting your email shows a generic “check your inbox” page without logging
you in. An eligible new address receives setup email within delivery limits.
Existing accounts receive no duplicate-registration notice; their credentials
and current setup code stay unchanged.

Open the setup link and enter:

- The security code from the same email
- A display name
- Your affiliation (optional)
- Your country (optional)
- A password and its confirmation

Use 12–200 characters for your password. Passwords are rejected if they match
the common-password list or contain your email local part or a display-name
word of at least four characters, ignoring case.

Submitting the completed setup form verifies your email, saves your chosen
password and profile, and activates the account. You are then directed to
login to enroll your authenticator. Opening the link alone does not complete
setup, and completing setup does not log you in.

If you are already signed in to another account, setup does not switch that
session. Sign out before logging in with the newly completed account.

The operator may disable new registration. Setup links already issued can
still be completed, and eligible pending accounts can still request a
replacement link.

If institutional login is enabled, use your institutional identity and its
required MFA. First sign-in creates a pending account for administrator review,
not a session. After approval, sign in again with the same institutional
identity; local password and authenticator setup are not required. Matching
email addresses never merge institutional and local accounts.

If a new institutional identity presents an address reserved by an unverified
local signup, the archive can remove that nonadmin reservation and create a
new pending institutional account. No local password, authenticator, profile
or access approval is transferred, and the old setup code stops working.
Administrator review is still required. A verified local account remains
separate and blocks the colliding institutional signup; contact the operator
instead of expecting automatic linking. Existing institutional accounts do
not remove local reservations when their institutional email changes.

## Setup links and email verification

Setup security codes last 24 hours and can be used once. Opening the public
link displays the password and profile form without checking or consuming the
code. Paste the code from the same email when completing that form.

Use **Need a new verification email?** on the login page. An eligible resend
keeps the same code and expiry while it is live; expired codes can be replaced.
Delivery limits apply.

An administrator-cancelled setup cannot be restarted through anonymous resend.
Contact the operator if your setup has been cancelled.

Unverified local accounts are normally removed after seven days; the operator
can change that period.

## Setting up two-factor authentication

After completing account setup, log in with your email and password to open
authenticator enrollment.

Use a TOTP-compatible authenticator to scan the QR code. Save the ten recovery
codes separately from that device, then submit a six-digit authenticator code
and one recovery code. The recovery code used to confirm enrollment remains
usable.

The pending authenticator seed lasts ten minutes. Refreshing setup replaces
the recovery codes, so save the newly displayed set before confirming.
Until enrollment finishes, the session has restricted access.

Completion ends all account sessions and returns to login. Sign in with your
password and a fresh authenticator code. Enrollment does not raise your tier.

## Using emailed action links

Setup, password-reset and email-change messages contain a public link and a
separate security code. Open the link in your browser, copy the code from the
same email into the form, complete the remaining fields and submit. Opening
the link alone changes nothing. This flow does not use JavaScript or fill the
code automatically. Paste the code itself, not the link, into the code field.

Keep the message and code private. The public link alone cannot authorize an
action or retrieve the code. Ask for a new message if you no longer have its
code. The generic form does not confirm that an account or usable request
exists; an expired, replaced, used or cancelled code is rejected when submitted.

## Forgotten passwords

Choose **Forgot password?** and submit your email. Active local accounts
receive a queued, single-use link valid for 30 minutes.

Open the public link, paste the security code from the same email, enter a
fresh six-digit authenticator code and choose a new password that meets the
normal rules and differs from your current password. Completion ends all account
sessions and sends a notification. Wait for a new authenticator code, then log
in again. Your authenticator and saved recovery codes remain configured.

A valid reset capability permits at most five submissions per account in a
30-minute window. Requesting another email does not reset that allowance.
Normal login remains available. If you also lost your authenticator, or never
completed its enrollment, contact the operator: this reset form cannot bypass
two-factor authentication. See the [recovery policy](../runbooks/credential-recovery.md).

## Changing your password

Open **Account → Change Password**. Enter your current password, new password
and confirmation, and a fresh authenticator code. A code used to log in or
perform another action cannot be reused; wait for the next code if needed.
Success signs out every device, cancels pending authentication actions and
sends a notification. Log in again using the new password and a new code.
Your authenticator and saved recovery codes remain configured.

The request response does not reveal account eligibility; processing time
may differ. Institutional passwords are managed by the identity provider.

## Changing your authenticator

If you still have access to your current authenticator, you can switch to a
new one from your account page. First submit your password and a current code.
The site displays a new QR code; scan it and confirm a code from the new
authenticator within five minutes.

Your old authenticator remains active until confirmation. Success ends all
sessions, so log in again. Your saved recovery codes remain valid.
Too many invalid confirmations discard only the pending change.

If your authenticator is lost entirely, contact an archive administrator.
A different local administrator must verify your identity and authorize a
30-minute recovery window. The administrator cannot see or generate your
saved recovery codes.

Then use **Recover authenticator** on the login page and enter your email,
password, and one saved recovery code. Successful recovery creates a
ten-minute setup session. Enroll the replacement authenticator and confirm
a fresh recovery-code set. The old recovery codes are replaced and all
sessions end, requiring a new login.

Each saved recovery code is one-time and allows at most three password
attempts. After three wrong passwords, that code can no longer be used;
your other unused codes remain available. Unknown codes do not lock your
account. The page uses the same error for an incorrect email, password,
or recovery code.

A temporary lock caused by ordinary sign-in failures does not block an
administrator-authorized recovery. Successful recovery clears that stale
lock state.

Sensitive account actions share a small attempt allowance for the current
session. Successful submissions count as well as rejected ones. If you
exhaust the allowance, only that browser session ends and you must log in
again. Your account and sessions on other devices remain active.

## Requesting a higher access tier

After account setup, request **registered** or **vetted** access using the
contact address on **Account** or **About**. Include:

- Your name, affiliation, and the email address tied to your account
- A short description of the research project the access is for
- Any relevant institutional ethics approvals or consent documentation

An administrator grants access after manual review. There is no automated
approval flow.

## Logging out and session expiry

Sessions expire after thirty minutes of inactivity or eight hours from login
by default; the operator may shorten them. Use **Logout** to end a session.

Logging out removes the session from the server, as well as its browser
cookie. A copied cookie cannot restore that session.

When institutional login is enabled, logout also passes through the archive's
Shibboleth service provider, including for local accounts. Wider
identity-provider logout depends on the provider. On shared computers,
also sign out there and close every browser window.

If an administrator deactivates your account, all of its sessions end as
part of the deactivation.

## Deleting your account

For a local account, open **Account**, choose **Delete account**, and read the
confirmation page. Submit your password, a fresh six-digit authenticator code
and the explicit deletion confirmation. A code just used to sign in or perform
another action cannot be reused; wait for a new code if needed.

Deletion is immediate and permanent. It removes your profile, credentials,
sessions on every device, saved recovery codes, pending authenticator changes,
promotion requests involving your account and email-outbox rows linked to it.
Previously issued setup, password-reset and email-change links cannot restore
the deleted account. A later registration creates a new account and requires
normal setup and approval.

The last active administrator cannot delete their account. Another active
administrator must remain. If you cannot complete password/authenticator proof,
contact the operator; account recovery and identity verification still apply.

Institutional accounts require an archive administrator to delete the archive
account. This does not delete the institutional identity. Signing in through
the institution again may create a new pending archive account, which requires
new approval.

Deletion retains a pseudonymous security-audit event. Existing audit history,
backups, email already delivered and records held by your institution follow
their separate retention procedures. Contact the operator about a wider
personal-data request; see the [deletion procedure](../runbooks/account-deletion.md)
and [retention/DSAR template](../runbooks/retention-dsar-template.md).

## Your account page

**Account** shows your profile, authentication method, access tier, join date,
and last login.

Local users can edit their display name, request an email change after
proving their password and a fresh authenticator code, change their password or authenticator, and delete their account
after password and fresh authenticator proof. Institutional names
and email addresses are managed by the institution.

Email changes send confirmation to the new address and a notice to the old
address. Confirm within one hour. Success changes the verified address and
ends all account sessions. Password reset, account deactivation, or
administrator unlock can invalidate a pending email change.

Administrators changing their own email must use **Account → Change Email**;
the administrator form assists other users and cannot bypass fresh proof.


## Recovery email and temporary login locks

Repeated recovery requests keep an existing email security code valid until its
original expiry. Delivery and recipient limits apply even when requests come
from different networks. Check your inbox and spam folder before requesting a
resend; a resend uses the same code and does not extend its lifetime.

For an established local account, the recovery page can either change your
password or sign you in without changing it. Both require the email code and a
fresh authenticator code. The sign-in option also works during a temporary
login lock caused by failed login attempts. Completing either option consumes
the email code and revokes previous account sessions. If your authenticator is
unavailable, contact the archive's support team for account recovery.
