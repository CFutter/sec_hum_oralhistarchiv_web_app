# Browsing & Searching

## The home page

Home shows the live dataset total, up to three recent records and the oldest
successful rebuild among selected sources. Freshness stays unknown until every
selected source has rebuilt and may be cached for an hour. Open a recent record
or use the search box to continue.

Two prominent entry points sit at the top of the page:

- **Search box** — type a phrase, hit return, and you land on the search page with your query already applied.
- **Browse all datasets** — opens the search page with no filters set, showing the most recently updated entries first.

## The search page

The search page has two parts: a sidebar of filters and a results list.

### Free-text search

Search matches visible titles, descriptions, project text, keywords and author names. Plain words use full-text search plus case-insensitive substring fallback: `beispiel` can match “Beispielstadt”. Quotes, `OR` between terms and a leading/separated minus select web-search operators. Other punctuation is literal; `%`, `_` and backslash always stay literal.

Each searched field must be visible at your tier under its record, field and source requirements. Restricted values never contribute matches.

### Filters

Three exact-match filters live in the sidebar:

| Filter | What it does |
|---|---|
| **Keyword** | Restrict to datasets tagged with one specific keyword |
| **Language** | Restrict to datasets containing interviews in a specific language |
| **Access level** | Match the source's *public* or *restricted* material label; the source decides download permission |

Filters combine with AND. If you set the language to *German* and the keyword to *Migration*, you only see German-language datasets tagged with Migration. Any free-text query you also typed continues to apply on top.

Keyword suggestions require at least two occurrences among sampled recent visible records. Keyword/language suggestions and filters respect your tier; access-level filtering applies to every record. Suggestions are incomplete, so you may type another exact value.

### Results and pagination

Results show public title/access level and each permitted author, description, keyword and language field. Restricted fields show their required tiers.

The operator sets page size (default 20). Use numbered pages 1–100, then previous/next continuation links. Bookmarks can expire after catalogue, policy or account changes; restart the search when prompted.

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
- A resource or source-record link when available, otherwise a contact address

The detail page shows each field permitted by the strictest dataset, field and source requirement. Restricted fields explain the required tier and how to request access. Public discovery details remain visible unless the record is hidden or withheld.

Some source links recheck your current metadata access and record an access
event before redirecting. A previously obtained link can stop working after a
dataset is hidden or its required tier rises. The originating repository still
controls access to recordings and other materials; following a link does not
guarantee permission to download them.

## Why a result might disappear

A few reasons a dataset you saw last week might not show up today:

- **A filter is set you forgot about.** Filters persist as URL parameters, so if you bookmarked a search you may still have the filter applied. Use *Browse all datasets* to start fresh.
- **The source policy or your access tier changed.** Full metadata may become hidden, but the public title/access level remain discoverable.
- **The source withdrew the dataset.** Announced deletions are processed by incremental sync; silent disappearances require a successful full rebuild. Schedules, source failures, and deletion safeguards can delay removal.

## Filter suggestions and large searches

Each filter suggests up to 50 values from the 200 most recently modified records, limited to the first 100 keywords/languages per record. Hidden fields above your tier are excluded. You can type an exact value outside the suggestions; filtering searches the full catalogue.

Administrator-hidden records and records awaiting a valid upstream correction are excluded at every tier.

