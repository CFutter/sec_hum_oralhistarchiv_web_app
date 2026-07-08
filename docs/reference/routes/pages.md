# Page Routes

The four user-facing page routes: home, search, dataset detail, and about. All four are GET-only and rendered server-side. They derive the requester's effective tier (`request.state.user.access_tier`, or `public` for guests) and pass it into the dataset service calls — the services return data that is already tier-filtered and redacted, so the routes and templates never handle an unredacted row for a below-tier viewer. The detail route additionally emits the `dataset_access` audit event for restricted-tier datasets.

For the visibility filtering logic see [Architecture → Access Control & Visibility](../../architecture/access-control.md).

::: app.routes.pages
