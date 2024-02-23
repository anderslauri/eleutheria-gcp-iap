# Open Programmatic Identity Aware Proxy for Google Cloud
Open implementation of Programmatic Identity Aware Proxy for Google Cloud. Used, in example, by `nginx` or `traefik` for authentication. 
Verifies JWT issued by Google Cloud Service Account. Ensuring validity and signature verification, as well as, ensurning subject 
of claim `email` have role binding `roles/iap.httpsResourceAccess` inside project. Conditional bindings are supported, i.e one can
configure a role binding to be restricted only to a specific `host` or `path` - and this will be recognized and evaluated in request.

The following token types are supported for Google Service Account:

- `ID-Token`
- `Self Signed JWT`

Please reference [Google Cloud Token Types][Google Cloud Token Types] for more information.

## Why?
`Identity Aware Proxy` for Google Cloud is only available in `BeyondCorp Enterprise`. There is other solutions available on GitHub,
however, none of these don't really fit the frame that I would like have for workload to workload authentication. So here we are.

## Authentication of Google Cloud Service Account

1. Signature verification using `JWK`. `JWK` is identified automatically given type of JWT.
2. `iat` and `exp` claim verification. Default clock skew is 30 seconds, meaning, `iat - <30 seconds>` and `exp + <30 seconds>`.
3. `aud` claim to equal request url.
4. Role `roles/iap.httpsResourceAccessor` is verified given email claim. Role binding can be given directly on project
   or via membership in group in Google Workspace. If conditional binding is present - this binding is evaluated.

:exclamation: `{1..3}` follow [JWT-verification as described by Google Cloud][JWT-Verification]. Step `4` is custom step following
principles of `Identity Aware Proxy`. Principles, as we don't support `client_id` as part of claim `aud` - only url.

:exclamation: Given successful validity and signature verification of JWT. Value of claim `email` is cached. 
Cache key is hash, in `SHA256`, of `(JWT || request url)`. `ttl` for cache is `exp - <interval of cleaning routine>`. Once 
token is found in cache - only step `4` is performed per each request. This is done for performance reasons.

## Role bindings
:warning: All role bindings are consumed asynchronously given a defined time interval (see configuration). This may or
may not be acceptable - depends on your choice. Bindings are kept in memory for performance. Default interval is `5min`. 
For the future, consuming `audit iam events` should be implemented to ensure a close to real time change of bindings.

### Conditional bindings
`request.path`, `request.host` and `request.time` are supported with conditional bindings with role `roles/iap.httpsResourceAccessor`.
All conditional bindings in Google Cloud are persisted and compiled in memory. If a role has a conditional binding, this binding is 
compiled and evaluated in memory using `cel-go`. All parameters are available per request.

:exclamation: Conditional bindings compiles into a program which is evaluated based on request parameters. Each program is cached and
re-used for performance reasons. Cache key is the expression itself. This is done for performance reasons.

## How to run
:exclamation: Use `Dockerfile` as example.

Configuration is based [pkl-lang][pkl-lang]. Use `pkl` through `wsl` for Windows.

1. Compile configuration using `pkl-gen-go default_config.pkl`.
2. Build application.
3. Ensure `pkl` is available in `$PATH`. Both `default_config.pkl` and `app_config.pkl` must be present in same directory as binary.

### Google Service Account Permissions
:exclamation: `Groups Reader` is required on Google Workspace. Reference [Google Workspace Administrator Roles][Google Workspace Administrator Roles].

:exclamation: `get-iam-policy` is required to list all bindings for role `roles/iap.httpsResourceAccess`. Custom role is recommended.

:exclamation: `Admin API` is required on project to enable access to `Directory API`.

## Endpoints 

### /auth (GET)
Authentication endpoint. Return code `200 OK` given successful authentication. `407 Proxy Authentication Required`
is given in case of unsuccessful authentication.

#### Headers
:warning: `X-Original-URI`, i.e. from `nginx` has assumed trust.

1. `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization`.
2. `X-Original-URI` is configured to be present. This can be changed using `HeaderMapping` in configuration.

### /healthz (GET)
Kubernetes health endpoint for liveness and readiness. Return code `200 OK`.

## Technical Debt
1. Only role bindings on a project level is taken into consideration. Folders and organization not implemented.
2. Cache behavior to be cleaned up. Implement support for `MemoryStore`.
3. Consume `IAM Audit Events` to ensure close to real time changes to policy bindings for user.
4. Implement proxy feature.

[Google Workspace Groups API]: <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups> "Google Workspace Groups API"
[Google Workspace Administrator Roles]: <https://support.google.com/a/answer/2405986> "Google Workspace Administrator Roles"
[Google Cloud Token Types]: <https://cloud.google.com/docs/authentication/token-types> "Google Cloud Token Types"
[Programmatic Authentication]: <https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header> "Programmatic Authentication"
[JWT-verification]: <https://cloud.google.com/docs/authentication/token-types#id-aud> "JWT-verification"
[cel-go]: <https://github.com/google/cel-go> "cel-go"
[pkl-lang]: <https://pkl-lang.org/go/current/index.html> "pkl-lang"
