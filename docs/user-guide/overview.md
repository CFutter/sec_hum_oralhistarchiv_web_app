# User Guide — Overview

The Oral History Archive is a search and browse portal for oral history research datasets. It collects the *descriptions* of datasets — titles, abstracts, authors, keywords, languages, licenses, citation information — from external repositories and makes them searchable in one place. This page orients you; the two companion pages go deeper on [searching and browsing](browsing.md) and on [accounts and access tiers](accounts.md).

## What the archive is (and is not)

The archive holds **metadata**, not the recordings or transcripts themselves. When you find a dataset you want to work with, the detail page gives you a download link or a link to the source repository's landing page — for restricted materials, the actual access request goes through the source repository's own process. Think of the archive as the catalogue room, not the vault.

The catalogue is refreshed automatically from the source repository (currently SWISSUbase) on a schedule, so what you see reflects the upstream state within roughly an hour; the home page shows when the catalogue was last fully reconciled.

## What you can do without an account

Everything essential. Anyone — logged in or not — can:

- Browse and search the full catalogue
- Filter by keyword, language, and access level
- Read the **full metadata of public-tier datasets**
- See the **title and access level** of every other dataset

No account is ever required just to *find out that a dataset exists*.

## What an account adds

Some datasets have metadata that is itself sensitive — descriptions that name interview subjects, for example. Those datasets carry a higher *visibility tier*, and their full metadata is only shown to users at that tier or above:

- **Registered** — create an account, verify your email, and enrol an authenticator app. You then see the full metadata of registered-tier datasets on top of everything public.
- **Vetted** — granted manually by the archive administrators on request, for researchers who need the most sensitive descriptions. See [Accounts & Access Tiers](accounts.md#requesting-a-higher-access-tier) for how to apply.

Restriction is enforced on the server: hidden fields are removed before the page is built, so they are not present in the page source either.

## Two kinds of "restricted"

Two independent labels appear throughout the site, and they answer different questions:

| Label | Question it answers | Where you see it |
|---|---|---|
| **Access level** (`public` / `restricted`) | Can the actual materials be downloaded directly, or must you request them from the source repository? | Badge on every result card and detail page — visible to everyone |
| **Visibility tier** (`public` / `registered` / `vetted`) | How much of the *description* can you read? | You notice it only indirectly, when a dataset shows just its title with a note that the rest requires a higher tier |

A dataset can be freely describable but restricted to download, or the other way around. If a detail page looks unusually empty, you are seeing the visibility tier at work — the page will say so and explain how to gain access.

## Finding your way around

- **Home** — collection statistics, the most recently added or updated datasets, a search box, and *Browse all datasets*.
- **Search** — the main working page: free-text search plus the filter sidebar. See [Browsing & Searching](browsing.md).
- **Dataset detail** — everything known about one dataset, with the download or landing-page link.
- **About** — project background and the administrators' contact address (also where tier requests go).
- **Login / Account** — registration, login, and self-service account management. See [Accounts & Access Tiers](accounts.md).

The site is plain server-rendered HTML — no JavaScript required — so it works in any browser, with screen readers, and over slow connections.
