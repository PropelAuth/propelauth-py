<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth Python SDK

A python library for managing authentication, backed by [PropelAuth](https://www.propelauth.com/?utm_campaign=github-python). 

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/python)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```bash
pip install propelauth_py
```


## Initialize

`init_base_auth` performs a one-time initialization of the library. 
It will verify your `api_key` is correct and fetch the metadata needed to verify access tokens with [validate_access_token_and_get_user](#protect-api-routes).

```py
from propelauth_py import init_base_auth

auth = init_base_auth("YOUR_AUTH_URL", "YOUR_API_KEY")
```

## Protect API Routes

After initializing auth, you can verify access tokens by passing in the Authorization header (formatted `Bearer TOKEN`) to `validate_access_token_and_get_user`.
You can see more information about the User object returned in [User](https://docs.propelauth.com/reference/backend-apis/python#user).

```py
auth_header = # get authorization header in the form `Bearer {TOKEN}`
try:
   user = auth.validate_access_token_and_get_user(auth_header)
   print("Logged in as", user.user_id)
except UnauthorizedException:
   print("Invalid access token")
```

## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User object](https://docs.propelauth.com/reference/backend-apis/python#user).

### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization. This can be done using the [User](https://docs.propelauth.com/reference/backend-apis/python#user) object.

```py
auth_header = # get authorization header in the form `Bearer {TOKEN}`
org_id = # get org id from request
try:
    user = auth.validate_access_token_and_get_user(auth_header)
    org = user.get_org(org_id)
    if org is None:
        # return 403 error
    print(f"You are in org {org.org_id}")
except UnauthorizedException:
    print("Invalid access token")
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/python#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/python#org-member-info) objects.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```py
## Assuming a Role structure of Owner => Admin => Member

auth_header = # get authorization header in the form `Bearer {TOKEN}`
org_id = # get org id from request
try:
    user = auth.validate_access_token_and_get_user(auth_header)
    org = user.get_org(org_id)
    if (org is None) or (org.user_is_role("Owner") == False):
        # return 403 error
    print(f"You are an Owner in org {org.org_id}")
except UnauthorizedException:
    print("Invalid access token")
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/python#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/python#org-member-info) objects.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. 
You can create these permissions in the PropelAuth dashboard.

```py
auth_header = # get authorization header in the form `Bearer {TOKEN}`
org_id = # get org id from request
try:
    user = auth.validate_access_token_and_get_user(auth_header)
    org = user.get_org(org_id)
    if (org is None) or (org.user_has_permission("can_view_billing") == False):
        # return 403 error
    print(f"You can view billing information for org {org.org_id}")
except UnauthorizedException:
    print("Invalid access token")
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more. 
See the [API Reference](https://docs.propelauth.com/reference) for more information.

```py
from propelauth_py import init_base_auth

auth = init_base_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

magic_link = auth.create_magic_link(email="test@example.com")
```

## Questions?

Feel free to reach out at support@propelauth.com
