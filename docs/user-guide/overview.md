# User Guide — Overview

The Oral History Archive makes oral-history dataset descriptions searchable. See [Browsing & Searching](browsing.md) and [Accounts & Access Tiers](accounts.md).

## What the archive is (and is not)

The archive holds **metadata**, not the recordings or transcripts themselves. When you find a dataset you want to work with, the detail page gives you a download link or a link to the source repository's landing page — for restricted materials, the actual access request goes through the source repository's own process. Think of the archive as the catalogue room, not the vault.

The catalogue syncs with SWISSUbase on the operator's schedule. Source failures or reconciliation safeguards can delay changes; the home page shows the last successful full reconciliation.

## What you can do without an account

Everything essential. Anyone — logged in or not — can:

- Browse and search the full catalogue
- Filter by keyword, language, and access level
- Read the **full metadata of public-tier datasets**
- See the **title and access level** of every other dataset

No account is ever required just to *find out that a dataset exists*.

## What an account adds

Some datasets have metadata that is itself sensitive — descriptions that name interview subjects, for example. Those datasets carry a higher *visibility tier*, and their full metadata is only shown to users at that tier or above:

- **Registered** — granted by an administrator after account setup; reveals public and registered metadata.
- **Vetted** — granted manually by the archive administrators on request, for researchers who need the most sensitive descriptions. See [Accounts & Access Tiers](accounts.md#requesting-a-higher-access-tier) for how to apply.

Restriction is enforced on the server: hidden fields are removed before the page is built, so they are not present in the page source either.

## Two kinds of "restricted"

Two independent labels appear throughout the site, and they answer different questions:

| Label | Question it answers | Where you see it |
|---|---|---|
| **Access level** (`public` / `restricted`) | Can the actual materials be downloaded directly, or must you request them from the source repository? | Badge on every result card and detail page — visible to everyone |
| **Visibility tier** (`public` / `registered` / `vetted`) | Minimum tier for full metadata | Restricted-result notice; required tier on the detail page |

A dataset can be freely describable but restricted to download, or the other way around. If a detail page looks unusually empty, you are seeing the visibility tier at work — the page will say so and explain how to gain access.

## Navigating the site

- **Home** — collection statistics, the most recently added or updated datasets, a search box, and *Browse all datasets*.
- **Search** — the main working page: free-text search plus the filter sidebar. See [Browsing & Searching](browsing.md).
- **Dataset detail** — everything known about one dataset, with the download or landing-page link.
- **About** — project background and the administrators' contact address (also where tier requests go).
- **Login / Account** — registration, login, and self-service account management. See [Accounts & Access Tiers](accounts.md).

The site uses server-rendered HTML and forms; its core flows do not require JavaScript.
