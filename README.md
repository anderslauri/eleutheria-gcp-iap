# Open Identity Aware Proxy for Workloads on Google Cloud
Authentication service/proxy, i.e. used by `nginx` or `traefik` in Kubernetes. Verifies JWT, issued by Google Cloud Platform, subject has membership of specified group in Google Workspace (or within role in project). The following types of JWT are supported:

- `ID-Token`
- `Self Signed JWT`

For more detailed information about ID-Token and Self Signed JWT, please reference [Google Cloud Token Types][Google Cloud Token Types]. Authentication (inc. verification of integrity and validity of JWT) is done accordingly to the following steps.

1. Signature verification through `JWK`. Endpoint for `JWK` is identified automatically given type of JWT.
2. `iat` and `exp` claim verification. Please note. Allowed clock skew is 30 seconds, meaning, `iat - <30 seconds>` and `exp + <30 seconds>`.
3. `aud` verification based on forwarded header of original requested url (by /auth endpoint) .
4. Role `roles/iap.httpsResourceAccessor` is verified given email of JWT. Either directly as role binding in project
   or indirectly via membership in group in `Google Workspace`.

`{1..3}` follow [JWT-verification as described by Google Cloud][JWT-Verification].

## Authentication and authorization management
Following `Identity Aware Proxy`. Access is managed using role `roles/iap.httpsResourceAccessor` in project, 
either directly via email or indirect via membership in group in `Google Workspace`. Conditional expressions are supported given scope of `Identity Aware Proxy`.

### Conditional expressions
`request.path`, `request.host` and `request.time` are supported in conditional expressions. These expressions are compiled in memory
and validated against the parameters as provided through the `/auth`-endpoint.

## Forwarded Headers
The following headers are required for `/auth`-endpoint.

### Authentication
One of `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization` must be present. If `X-Forwarded-Proxy-Authorization` is found `X-Forwarded-Authorization` is ignored.
This logic follows [programmatic authentication by Identity Aware Proxy][Programmatic Authentication]. These headers are not configurable.

### Host and protocol
- Request URI resolves to header `X-Original-URI`.

## Required Permissions Google Service Account
Google service account must have enough permissions to retrieve all policy bindings within the project, also `Admin SDK`
must be enabled on the project to enable access to Google Workspace. Please reference [Google Workspace Administrator Roles][Google Workspace Administrator Roles].

## Endpoints 

### /auth (GET)
Primary authentication endpoint. Return code `200 OK` given successful verification and integrity validation of JWT and membership in Google Workspace group, else `407 Proxy Authentication Required`. No body is returned.

#### Parameters
1. `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization`.
2. `X-Original-URI` must be present.

### /healthz (GET)
Kubernetes health endpoint for liveness and readiness. Return code `200 OK` with no body.

[Google Workspace Groups API]: <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups> "Google Workspace Groups API"
[Google Workspace Administrator Roles]: <https://support.google.com/a/answer/2405986> "Google Workspace Administrator Roles"
[Google Cloud Token Types]: <https://cloud.google.com/docs/authentication/token-types> "Google Cloud Token Types"
[Programmatic Authentication]: <https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header> "Programmatic Authentication"
[JWT-verification]: <https://cloud.google.com/docs/authentication/token-types#id-aud> "JWT-verification"