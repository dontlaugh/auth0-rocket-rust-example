
Oauth with Rocket against Auth0

https://auth0.com/docs/application-auth/current/server-side-web

### TODO

* take pem from .well-known, extract public key
* make it work with other jwt library? my fork?
* learn to do configurable features
  * Cargo.toml,
* validate the returned JWT
* document the request/data flow
* mention x509 gotchas
* put session into cookie (hash something from the jwt)
* store the same hash in the database: {jwt hash} -> expires timestamp
* request guard for JWT something



