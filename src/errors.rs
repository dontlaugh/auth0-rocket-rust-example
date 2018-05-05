use failure;

#[derive(Fail, Debug)]
#[fail(display = "bad configuration value")]
pub struct ConfigError;

#[derive(Fail, Debug)]
#[fail(display = "You must set AUTH0_CLIENT_SECRET")]
pub struct MissingAuth0Secret;

