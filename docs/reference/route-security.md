# Route Security Contract

`SecureAPIRouter` is the only supported way to declare an application HTTP route. Each router has one `RouteAccess` class and owns the dependencies for that class. For every method other than `GET`, `HEAD`, and `OPTIONS`, it also installs form Content-Type validation and HMAC-bound CSRF verification; only exact `POST /verify-email` and `POST /account/confirm-email` omit CSRF under the capability policy.

Public, open-during-enrolment, capability, and TOTP-enrolment routes are closed exact method/path inventories. Full-session and local-full-session routes are protected by their router dependency by default, while every `/admin` route must use the admin policy. The validator also rejects duplicate route keys, plain FastAPI routes, unexpected mounts or Starlette routes, and WebSockets. It runs once immediately after route inclusion and again during lifespan startup.

::: app.route_security