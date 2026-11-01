# User Guide — Overview

The Oral History Archive makes oral-history dataset descriptions searchable. See [Browsing & Searching](browsing.md) and [Accounts & Access Tiers](accounts.md).

## What the archive is (and is not)

The archive holds **metadata**, not the recordings or transcripts themselves.
When you find a dataset you want to work with, its detail page can provide a
resource or source-record link if you have full metadata access and a usable
link is available. The originating repository controls access to the materials;
your metadata tier does not grant download permission there.

The catalogue syncs with its configured sources on the operator's schedule. Source failures or reconciliation safeguards can delay changes; the home page shows the last successful full reconciliation.

## What you can do without an account

Anyone — logged in or not — can:

- Browse listed datasets and search their public information
- Filter by available keywords and languages, and by access level
- Read metadata fields whose access requirement is **public**
- See the **title and access level** of each listed dataset

Datasets hidden by an administrator are excluded from the catalogue at every
tier. Public browsing covers the datasets that remain listed, rather than
every record ever held by the archive.

## What an account adds

Some metadata is itself sensitive — descriptions that name interview subjects,
for example. The dataset's *visibility tier* sets a minimum for its protected
metadata. Individual fields and their source can require a higher tier; the
strictest requirement applies to each field. For example, a public-tier dataset
can have a description requiring registered access or keywords requiring vetted
access. Full metadata requires permission for every field.

- **Registered** — granted by an administrator after account setup; permits fields requiring public or registered access.
- **Vetted** — granted by an administrator after review; permits fields requiring public, registered or vetted access in listed datasets. See [Accounts & Access Tiers](accounts.md#requesting-a-higher-access-tier) for how to apply.

Search and filters use only information available to your tier. Restricted
values are omitted from the response and are absent from page source.

## Two kinds of "restricted"

Two independent labels appear throughout the site, and they answer different questions:

| Label | Question it answers | Where you see it |
|---|---|---|
| **Access level** (`public` / `restricted`) | Does the source describe the materials as public or restricted? The source still controls access. | Badge on result cards and detail pages |
| **Visibility tier** (`public` / `registered` / `vetted`) | Dataset-wide minimum for protected metadata; individual fields can require a higher tier | Restriction notices on results and detail pages include the applicable field requirements |

A dataset can have public metadata while access to its recordings is restricted,
or sensitive metadata while its materials are public. A detail page can show
some fields and restrict others; its notices explain the required access tier
and how to request it.

## Navigating the site

- **Home** — the current dataset total, the most recently added or updated datasets, a search box, and *Browse all datasets*.
- **Search** — the main working page: free-text search plus the filter sidebar. See [Browsing & Searching](browsing.md).
- **Dataset detail** — permitted metadata for one listed dataset, with a resource or source-record link when allowed and available.
- **About** — project background and the administrators' contact address (also where tier requests go).
- **Login / Account** — registration, login, and self-service account management. See [Accounts & Access Tiers](accounts.md).

The site uses server-rendered HTML and forms; its core flows do not require JavaScript.
