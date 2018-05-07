#[derive(Fail, Debug)]
pub enum AuthError {
    #[fail(display = "jwt is expired")]
    Expired,
    #[fail(display = "audience field check failed")]
    AudienceMismatch,
    #[fail(display = "issuer field doesn't match fully-qualified Auth0 domain")]
    IssuerMismatch,
    #[fail(display = "malformed jwt: {}", repr)]
    MalformedJWT { repr: String },
}

#[derive(Fail, Debug)]
#[fail(display = "could not serialize: {}", name)]
pub struct SerializationError {
    pub name: String,
}

#[derive(Fail, Debug)]
#[fail(display = "could not deserialize: {}", name)]
pub struct DeserializationError {
    pub name: String,
}

#[derive(Fail, Debug)]
#[fail(display = "database error")]
pub struct DatabaseError;
