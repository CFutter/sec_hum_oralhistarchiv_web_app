# Browsing & Searching

## The home page

The home page shows the size of the collection (number of datasets, languages, and indexed keywords), the date the catalogue was last fully reconciled with the source, and the three most recently added or updated datasets. From here you can either jump straight into a search or click any of the recent datasets to open its detail page.

Two prominent entry points sit at the top of the page:

- **Search box** — type a phrase, hit return, and you land on the search page with your query already applied.
- **Browse all datasets** — opens the search page with no filters set, showing the most recently updated entries first.

## The search page

The search page has two parts: a sidebar of filters and a results list.

### Free-text search

The search box at the top matches your query against the title, description, project title, project description, keywords, and author names of every dataset in one go. Matching is case-insensitive substring search — typing `kassel` will find "Kassel" and "kasseler" alike. You don't need quotes, wildcards, or boolean operators. Special characters in your query are taken literally; you cannot accidentally write a SQL pattern.

For datasets above your tier, only title and access level match free text; hidden descriptions, authors, and keywords do not.

### Filters

Three exact-match filters live in the sidebar:

| Filter | What it does |
|---|---|
| **Keyword** | Restrict to datasets tagged with one specific keyword |
| **Language** | Restrict to datasets containing interviews in a specific language |
| **Access level** | Restrict to *public* (downloadable) or *restricted* (request required) datasets |

Filters combine with AND. If you set the language to *German* and the keyword to *Migration*, you only see German-language datasets tagged with Migration. Any free-text query you also typed continues to apply on top.

Keyword suggestions require at least two occurrences among sampled recent visible records. Keyword/language suggestions and filters respect your tier; access-level filtering applies to every record. Suggestions are incomplete, so you may type another exact value.

### Results and pagination

Visible results show title, authors, a description snippet, keywords, languages, and access level. Above-tier results show title, access level, and a restricted notice; open the detail page to see the required tier.

The results are paginated. The page size is configured by the operator (default: 20 per page). Pagination links appear at the bottom of the list when there is more than one page.

## The detail page

Clicking a result opens the detail page for one dataset. You'll see:

- The full title and, where present, the project title and project description
- The description
- The authors
- The languages covered
- The keywords
- The resource type and version
- The license and license URL (where present)
- The DOI and bibliographical citation (where present)
- A SWISSUbase resource/landing-page link when available, otherwise a contact address

If the dataset is restricted to a tier above yours, the detail page shows only the title and the access level, with a note explaining why other fields are hidden and how to request access.

## Why a result might disappear

A few reasons a dataset you saw last week might not show up today:

- **A filter is set you forgot about.** Filters persist as URL parameters, so if you bookmarked a search you may still have the filter applied. Use *Browse all datasets* to start fresh.
- **The source policy or your access tier changed.** Full metadata may become hidden, but the public title/access level remain discoverable.
- **The source withdrew the dataset.** Announced deletions are processed by incremental sync; silent disappearances require a successful full rebuild. Schedules, source failures, and deletion safeguards can delay removal.

## Filter suggestions and large searches

Each filter suggests up to 50 values from the 200 most recently modified records, limited to the first 100 keywords/languages per record. Hidden fields above your tier are excluded. You can type an exact value outside the suggestions; filtering searches the full catalogue.

Search exposes at most 10,000 numbered pages. If more matches exist, narrow the search; pagination does not link beyond that window.

