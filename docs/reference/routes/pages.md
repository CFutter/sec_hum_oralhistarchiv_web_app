# Page Routes

`GET /`, `/search`, and `/dataset/{dataset_id}` pass the resolved user's tier (public for guests) to dataset services and render redacted results. `GET /about` renders static context. Nonpublic detail requests emit `dataset_access`, including denied full views. Search pages are bounded to 10,000 and preserve filters in redirects/pagination.

For the visibility filtering logic see [Architecture → Access Control & Visibility](../../architecture/access-control.md).

::: app.routes.pages
