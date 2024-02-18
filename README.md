# Kubernetes Google Workspace Authentication
Authenticaton service, i.e. used by `nginx` or `traefik` in Kubernetes verifies JWT, issued by Google Cloud Platform, subject has membership of specified group in Google Workspace. The following types of JWT are supported:

- ID-Token
- Self Signed JWT

For more detailed information about ID-Token and Self Signed JWT, please reference [Google Cloud Token Types][Google Cloud Token Types]. Verification of integrity and validity follows the following steps.

1. 

## Required Ingress Annotation
- `gws.membership/<id|name|email>`. Please reference [Google Workspace Groups API][Google Workspace Groups API] for detailed description when to use `id`, `name` or `email`.
  Value of annotation key is equal to respective identifier. Annotation is used by service to query group for membership in Google Workspace.

## Required Forwarded Headers
The following headers are required.

### Authentication Headers
One of `X-Forwarded-Authorization` or `X-Forwarded-Proxy-Authorization` must be present. If `X-Forwarded-Proxy-Authorization` is found `X-Forwarded-Authorization` is ignored.
This logic follows [programmatic authentication by Identity Aware Proxy][Programmatic Authentication].

### X-Forwarded Headers



## Required Permissions
The following permissions are required.

### Google Workspace
Google service account must have, atleast, prebuilt administrative role `Group Reader` in Google Workspace. Please reference [Google Workspace Administrator Roles][Google Workspace Administrator Roles] for more information.

### Kubernetes

[Google Workspace Groups API]: <https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups> "Google Workspace Groups API"
[Google Workspace Administrator Roles]: <https://support.google.com/a/answer/2405986> "Google Workspace Administrator Roles"
[Google Cloud Token Types]: <https://cloud.google.com/docs/authentication/token-types> "Google Cloud Token Types"
[Programmatic Authentication]: <https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header> "Programmatic Authentication"
