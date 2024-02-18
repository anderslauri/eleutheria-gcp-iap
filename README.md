# Kubernetes Google Workspace Authentication
Authenticaton service, i.e. used by `nginx` or `traefik` in Kubernetes verifies JWT, issued by Google Cloud Platform, subject has membership of specified group in Google Workspace. The following types of JWT are supported:

- `ID-Token`
- `Self Signed JWT`

For more detailed information about ID-Token and Self Signed JWT, please reference [Google Cloud Token Types][Google Cloud Token Types]. Authentication (inc. verification of integrity and validity of JWT) is done accordingly to the following steps.

1. Signtature verification through `JWKS`. Endpoint for `JWKS` is identified automatically given type of JWT.
2. `iat` and `exp` claim verification. Please note. Allowed clock skew is 30 seconds, meaning, `iat - <30 seconds>` and `exp + <30 seconds>`.
3. `aud` verification based on forwarded header of original requested url.
4. Membership query (in Google Workspace) given value of `gws.membership` annotation for matching ingress.

`{1..3}` follow [JWT-verification as described by Google Cloud][JWT-Verification].

## Required Ingress Annotation
- `gws.membership/<id|name|email>`. Please reference [Google Workspace Groups API][Google Workspace Groups API] for detailed description when to use `id`, `name` or `email`.
  Value of annotation key is equal to respective identifier. Annotation is used by service to query group for membership in Google Workspace.

## Forwarded Headers
The following headers are required to complete integrity and signature validation of JWT and membership validation in Google Workspace group.

### Authentication
One of `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization` must be present. If `X-Forwarded-Proxy-Authorization` is found `X-Forwarded-Authorization` is ignored.
This logic follows [programmatic authentication by Identity Aware Proxy][Programmatic Authentication]. These headers are not configurable.

### Host and protocol
- Request URI resolves to header `X-Original-URI`.
- Request protocol resolves to header `X-Scheme`.

## Required Permissions
The following permissions are required.

### Google Workspace
Google service account must have, atleast, prebuilt administrative role `Group Reader` in Google Workspace. Please reference [Google Workspace Administrator Roles][Google Workspace Administrator Roles] for more information.

### Kubernetes
Kubernetes service account must have cluster wide rbac-bindings `list` and `get` for the following resources in Kubernetes:

- `namespace`
- `ingresses`

## Endpoints 

### /auth (GET)
Primary authentication endpoint. Return code `200 OK` given successful verification and integrity validation of JWT and membership in Google Workspace group, else `407 Proxy Authentication Required`. No body is returned.

#### Parameters
1. `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization`.
2. `X-Original-URI` and `X-Scheme` must be present.

### /healthz (GET)
Kubernetes health endpoint for liveness and readiness. Return code `200 OK` with no body.

[Google Workspace Groups API]: <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups> "Google Workspace Groups API"
[Google Workspace Administrator Roles]: <https://support.google.com/a/answer/2405986> "Google Workspace Administrator Roles"
[Google Cloud Token Types]: <https://cloud.google.com/docs/authentication/token-types> "Google Cloud Token Types"
[Programmatic Authentication]: <https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header> "Programmatic Authentication"
[JWT-verification]: <https://cloud.google.com/docs/authentication/token-types#id-aud> "JWT-verification"
