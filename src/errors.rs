use failure;
use failure::Error;

#[derive(Fail, Debug)]
#[fail(display = "bad configuration value")]
pub struct ConfigError;

#[derive(Fail, Debug)]
pub enum AuthError {
    #[fail(display = "AUTH0_CLIENT_SECRET is not set")]
    MissingAuth0Secret,
    #[fail(display = "jwt is expired")]
    Expired,
    #[fail(display = "audience field check failed")]
    AudienceMismatch,
}

#[derive(Fail, Debug)]
#[fail(display = "could not deserialize field")]
pub struct SerializationError;
