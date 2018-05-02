
Oauth with Rocket against Auth0

https://auth0.com/docs/application-auth/current/server-side-web

### TODO

* take pem from .well-known, extract public key
  * do the equivalent of: `openssl x509 -pubkey -noout -in coleman.pem  > coleman_pubkey.pem`
  * rusticata/x509-parser? or nom_pem?
* make it work with other jwt library? my fork?
* learn to do configurable features
  * Cargo.toml,
  * put funcs behind config flags
* validate the returned JWT
* document the request/data flow
* mention x509 gotchas
* code beautification: struct flattening for shared fields? Maybe, maybe not.
* put session into cookie (hash something from the jwt)
* store the same hash in the database: {jwt hash} -> expires timestamp
* request guard for JWT something
* hide secrets in Rocket.toml



