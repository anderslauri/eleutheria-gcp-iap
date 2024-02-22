# Open Identity Aware Proxy for Google Cloud
Authentication service/proxy, i.e. used by `nginx` or `traefik` in Kubernetes verifies JWT, issued by Google Cloud Platform, subject has membership of specified group in Google Workspace (or within project). The following types of JWT are supported:

- `ID-Token`
- `Self Signed JWT`

For more detailed information about ID-Token and Self Signed JWT, please reference [Google Cloud Token Types][Google Cloud Token Types]. Authentication (inc. verification of integrity and validity of JWT) is done accordingly to the following steps.

1. Signature verification through `JWKS`. Endpoint for `JWKS` is identified automatically given type of JWT.
2. `iat` and `exp` claim verification. Please note. Allowed clock skew is 30 seconds, meaning, `iat - <30 seconds>` and `exp + <30 seconds>`.
3. `aud` verification based on forwarded header of original requested url.
4. Membership query (in Google Workspace) given value of `gws.membership` annotation for matching ingress.

`{1..3}` follow [JWT-verification as described by Google Cloud][JWT-Verification].

## What about the name?
What about it?

## Role bindings in Google Cloud

Access is managed via role bindings in project where Google Service Account running the service is present.

## Forwarded Headers
The following headers are required to complete integrity and signature validation of JWT and membership validation in Google Workspace group.

### Authentication
One of `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization` must be present. If `X-Forwarded-Proxy-Authorization` is found `X-Forwarded-Authorization` is ignored.
This logic follows [programmatic authentication by Identity Aware Proxy][Programmatic Authentication]. These headers are not configurable.

### Host and protocol
- Request URI resolves to header `X-Original-URI`.

## Required Permissions
The following permissions are required.

### Google Workspace
Google service account must have, atleast, prebuilt administrative role `Group Reader` in Google Workspace. Please reference [Google Workspace Administrator Roles][Google Workspace Administrator Roles] for more information.

### Google Workspace

## Endpoints 

### /auth (GET)
Primary authentication endpoint. Return code `200 OK` given successful verification and integrity validation of JWT and membership in Google Workspace group, else `407 Proxy Authentication Required`. No body is returned.

#### Parameters
1. `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization`.
2. `X-Original-URI` and `X-Scheme` must be present.

### /healthz (GET)
Kubernetes health endpoint for liveness and readiness. Return code `200 OK` with no body.

## Caching
Multiple layers of caching exist to enhance throughput.

1. JWK-caching. Read frequently, changed seldom. Using `Copy on Write` cache for self-signed JWT,
   `Atomic.Value` keeps JWK from `accounts.google.com` in memory. Loaded on startup. Cleaning is done
    every one hour, if item count is above 500.
2. JWT-caching. Read frequently, changed frequently. Utilize `Sync.Map` with cleaning routine,
   `ttl` is `exp` of token minus routine interval. Only hash of token is kept. No reason else.
3. Ingress-caching. Read frequently, changed seldom. Using `Copy on Write` cache. No cleaning,
   if new ingress is detected with annotation. Recreate cache from all ingresses.
4. GWS-caching. Authorization caching, read frequently and changed frequently. Utilize `Sync.Map`,
   only kept in memory for 30min after request to query per user to GWS.

MemoryStore? Yes, should be easy. It's an interface implementation.

[Google Workspace Groups API]: <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups> "Google Workspace Groups API"
[Google Workspace Administrator Roles]: <https://support.google.com/a/answer/2405986> "Google Workspace Administrator Roles"
[Google Cloud Token Types]: <https://cloud.google.com/docs/authentication/token-types> "Google Cloud Token Types"
[Programmatic Authentication]: <https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header> "Programmatic Authentication"
[JWT-verification]: <https://cloud.google.com/docs/authentication/token-types#id-aud> "JWT-verification"