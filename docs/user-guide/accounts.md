# Accounts & Access Tiers

You do not need an account to browse and search the public part of the archive. You only need one if you want to see metadata that has been restricted to registered or vetted users.

## The three tiers

| Tier | How you get it | What it grants |
|---|---|---|
| **Public** | The default for everyone, including users who are not logged in | Full metadata of public-tier datasets; title and access level only for restricted-tier datasets |
| **Registered** | Create an account, verify your email, enrol an authenticator app | Everything *Public* sees, plus full metadata of registered-tier datasets |
| **Vetted** | Submit an access request to the archive administrators after registering | Everything *Registered* sees, plus full metadata of vetted-tier datasets — including strictly confidential fields |

The tier system is enforced on the server. Restricted fields are removed from the response *before* the page is rendered, so it is not possible to inspect the page source to recover hidden values.

## Registering for an account

Click **Login** in the navigation, then **Register**. You will be asked for:

- Your email address (used as your login name)
- A display name
- Your institutional affiliation (optional)
- Your country (optional)
- A password

The password must be at least 12 characters long. The system additionally rejects passwords that appear in a list of the 10 000 most commonly compromised passwords, and passwords that contain your email address or display name. Choose something memorable but not guessable — a passphrase of four random words is a good starting point.

Submitting the form creates the account and shows a "check your inbox" page — you are **not** logged in yet. A verification email is sent to the address you provided; you must click the link in that email before you can log in at all. (If the address was already registered, the page looks exactly the same and the existing account owner is notified by email instead — so the form cannot be used to find out whether an address has an account.)

If your deployment has **SWITCH edu-ID** login enabled, you can use that instead of registering locally; edu-ID users skip the local password and authenticator setup, since the second factor is handled by your identity provider.

## Verifying your email

The verification link is valid for 24 hours. Clicking it shows a confirmation page with a button — the address is only marked verified when you press it, so an email scanner following the link cannot use it up. If the link expires, you can request a new one from the login page ("Need a new verification email?"). Accounts that are never verified are automatically removed after a few days.

## Setting up two-factor authentication

Once your email is verified, log in with your email and password. Because your account has no authenticator yet, this first login takes you straight to the two-factor setup page — until enrolment is complete, your session can only reach that page (and logout). You will need an authenticator app on your phone — Google Authenticator, Microsoft Authenticator, Aegis, 1Password, Bitwarden, and most password managers all work. The setup page shows:

1. A QR code. Scan it with your authenticator app.
2. A six-digit code field. Enter the current code from your authenticator app to confirm enrolment.

Once confirmed, your session is upgraded to a full session and you can use the rest of the site. You will be asked for a code from your authenticator app on every login from then on.

> :material-information-outline: **Why is TOTP mandatory?**
> The archive is being prepared for Phase 2, when it will host metadata about sensitive research data. Building the habit of two-factor authentication into Phase 1 means there is no migration when sensitive data arrives — and it protects your account against credential stuffing today.

## Forgotten passwords

On the login page, click **Forgot password?**. Enter your email address. If an account exists for that address, the system sends a reset email containing a single-use link, valid for a short time (typically 30 minutes). Clicking the link takes you to a form where you can set a new password — the same strength rules apply, and you cannot reuse your current password.

The system does not reveal whether an email address is registered. The success message is the same whether or not the address exists, so the reset flow cannot be used to enumerate accounts.

## Changing your authenticator

If you still have access to your current authenticator, you can switch to a new one from your account page. The change requires a current code *and* a code from the new authenticator, so only someone holding the existing device can do it.

If your authenticator is lost entirely — so you cannot supply a current code — there is no self-service recovery. Contact the archive administrators; recovery is handled out of band.

## Requesting a higher access tier

After you have registered and verified your account, you can request *vetted* status by writing to the archive administrators at the email address shown on the *About* page. Include:

- Your name, affiliation, and the email address tied to your account
- A short description of the research project the access is for
- Any institutional ethics approvals or consent documentation that is relevant

Vetted access is granted by an administrator after manual review. There is no automated approval flow.

## Logging out and session expiry

Sessions last up to 8 hours from login by default, after which you are asked to log in again. You can log out manually at any time using the **Logout** link in the navigation. Logging out removes the session from the server, not just the cookie from your browser — so logging out from one device cannot be undone by re-using the cookie elsewhere.

If your account is deactivated by an administrator, all of its sessions end immediately as part of the deactivation.

## Your account page

Once logged in, the **Account** link in the navigation takes you to a page showing your email, display name, affiliation, country, current access tier, the date your account was created, and the date of your most recent login, and confirming that two-factor authentication is enabled. From the account area you can also update your display name, change your email address (a confirmation link is sent to the new address before the change takes effect), and rotate your authenticator.
