
## OAuth with Rocket + Auth0


### Configuration

Copy the example Rocket.toml file

```
cp Rocket.toml.example Rocket.toml
```

Edit the `client_id`, `redirect_uri`, and `auth0_domain` with your own values.

You must **also** set `AUTH0_CLIENT_SECRET` in your environment. We use an env
var to avoid leaking our secret key to the console during startup.

All values should be available from from [Auth0's management console](https://manage.auth0.com/) 
for your application. 


## Helpful Docs

* https://auth0.com/docs/application-auth/current/server-side-web
* https://auth0.com/docs/jwt
* https://auth0.com/docs/api-auth/tutorials/verify-access-token#validate-the-claims
* https://auth0.com/docs/jwks#verifying-a-jwt-using-the-jwks-endpoint
* https://auth0.com/docs/tokens/id-token#verify-the-signature:w
