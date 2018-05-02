#![feature(plugin)]
#![plugin(rocket_codegen)]
#![allow(warnings)] // dev only
#![feature(proc_macro)]
#![feature(proc_macro_non_items)]
#![feature(custom_derive)]

#[cfg(feature = "default")]
extern crate frank_jwt;
#[cfg(feature = "ring-crypto")]
extern crate jsonwebtoken;

extern crate openssl;
extern crate base64;
extern crate maud;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_codegen;
extern crate url;
extern crate x509_parser;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[cfg(feature = "default")]
use frank_jwt::{decode, encode, Algorithm};

#[cfg(feature = "ring-crypto")]
use jsonwebtoken::{decode, decode_header, Algorithm, TokenData, Validation};

use serde::Serialize;
use serde_json::ser::to_vec;

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use maud::{html, Markup};
use reqwest::header::ContentType;
use reqwest::mime::APPLICATION_JSON;
use rocket::config::ConfigError;
use rocket::fairing::AdHoc;
use rocket::http::uri::URI;
use rocket::http::{Cookie, Cookies, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{status, Redirect};
use rocket::State;
use url::Url;
use x509_parser::pem;

fn main() {
    let sessions = SessionMap(RwLock::new(HashMap::new()));
    let routes = get_routes();
    rocket::ignite()
        .mount("/", routes)
        .manage(sessions)
        .attach(AdHoc::on_attach(|rocket| {
            let conf = rocket.config().clone();
            let app_settings = AppSettings::from_rocket_config(&conf).expect("configuration error");
            Ok(rocket.manage(app_settings))
        }))
        .launch();
}

fn get_routes() -> Vec<rocket::Route> {
    routes![index, login, auth0_callback]
}

// FromForm deprecated? see:
// https://github.com/rust-lang/rust/issues/29644#issuecomment-359094330
#[derive(FromForm)]
struct CodeAndState {
    code: String,
    state: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    email: String,
}

#[get("/login")]
fn index() -> Markup {
    html!{
       body {
           h1 "hello world"
           a href="/auth0" "Login With Auth0!"
       }
    }
}

#[get("/protected")]
fn protected_authorized(email: Email) -> Result<String, Status> {
    Ok(String::from_str("great").unwrap())
}

#[get("/protected", rank = 2)]
fn protected_unauthorized() -> Redirect {
    Redirect::to("/login")
}

/// This route reads settings from our application state and redirects to our
/// configured Auth0 login page. If our user's login is successful, Auth0 will
/// redirect them back to /callback with "code" and "state" as query params.
#[get("/auth0")]
fn login(mut cookies: Cookies, settings: State<AppSettings>) -> Redirect {
    let state = random_state_string();
    cookies.add(Cookie::new("state", state.clone()));

    let ar = AuthorizeRequest {
        grant_type: String::from("authorization_code"),
        client_id: settings.client_id.clone(),
        client_secret: settings.client_secret.clone(),
        redirect_uri: settings.redirect_uri.clone(),
        state: state,
        auth0_domain: settings.auth0_domain.clone(),
    };
    let authorize_endpoint =  format!(
            "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&state={}",
             ar.auth0_domain,
             ar.client_id,
             URI::percent_encode(&ar.redirect_uri),
             ar.state,
             );

    Redirect::to(&authorize_endpoint)
}

/// Login callback. Auth0 sends a request to this endpoint. In the query string
/// we extract the "code" and "state" parameters, ensuring that "state" matches
/// the string we passed to Auth0's /authorize endpoint. Then we can use "code"
/// in a TokenRequest to the /oauth/token endpoint.
#[get("/callback?<code>")]
fn auth0_callback(
    code: CodeAndState,
    mut cookies: Cookies,
    sessions: State<SessionMap>,
    settings: State<AppSettings>,
) -> Result<String, Status> {
    let tr = TokenRequest {
        grant_type: String::from_str("authorization_code").unwrap(),
        client_id: settings.client_id.clone(),
        client_secret: settings.client_secret.clone(),
        code: code.code.clone(),
        redirect_uri: settings.redirect_uri.clone(),
    };

    let state = code.state.clone();
    if let Some(cookie) = cookies.get("state") {
        if state != String::from_str(cookie.value()).unwrap() {
            return Err(rocket::http::Status::Forbidden);
        }
    } else {
        return Err(rocket::http::Status::BadRequest);
    }

    // named yields a 'static reference; can we use it like a lookup here?
    cookies.remove(Cookie::named("state"));

    let token_endpoint = format!("https://{}/oauth/token", settings.auth0_domain);
    let client = reqwest::Client::new();
    let resp: TokenResponse = client
        .post(&token_endpoint)
        .header(ContentType(APPLICATION_JSON))
        .body(to_vec(&tr).expect("could not serialize TokenRequest"))
        .send()
        .expect("POST REQUEST")
        .json()
        .expect("could not deserialize response");

    let jwks_endpoint = format!("https://{}/.well-known/jwks.json", settings.auth0_domain);
    let mut jwt: JsonWebKeySet = client
        .get(Url::from_str(&jwks_endpoint).unwrap())
        .send()
        .unwrap()
        .json()
        .unwrap();

    let cert_endpoint = format!("https://{}/pem", settings.auth0_domain);
    let mut pem_cert: String = client
        .get(Url::from_str(&cert_endpoint).unwrap())
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("pem cert");
    println!("{}", pem_cert);

    use openssl::x509::X509Builder;
    let mut x = X509Builder::new();

    // https://auth0.com/docs/tokens/id-token#verify-the-signature
    // der'd up cert
    //let (_, derd) = pem::pem_to_der(&pem_cert.as_bytes()).unwrap();

    #[cfg(feature = "default")]
    {
        println!("default config");
        let (foo, baz) = decode(
            &resp.id_token,
            //&String::from_utf8(pem_cert).expect("from_utf8 failed"),
            &pem_cert,
            Algorithm::RS256,
        ).expect("decoding JWT should work, people");
    }

    #[cfg(feature = "ring-crypto")]
    {
        println!("ring-crypto config");
        let headers = decode_header(&resp.id_token).expect("could not decode headers");
        let token_data: TokenData<HashMap<String, String>> = decode(
            &resp.id_token,
            &jwt.keys[0].x5c[0].as_bytes(),
            &Validation::new(headers.alg),
        ).unwrap();
        let claims = &token_data.claims;
    }

    Ok(String::from("Thanks"))
}

pub fn random_state_string() -> String {
    use rand::{thread_rng, Rng};
    let random: String = thread_rng().gen_ascii_chars().take(30).collect();
    random
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn write_file(path: &str, bytes: &[u8]) {
    use std::io::Write;
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(bytes).unwrap()
}

/// Send a AuthorizeRequest to the Auth0 /authorize endpoint.
struct AuthorizeRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    state: String,
    redirect_uri: String,
    auth0_domain: String,
}

/// Send TokenRequest to the Auth0 /oauth/token endpoint.
#[derive(Serialize, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    id_token: String,
    token_type: String,
}

/// Maps session keys to email addresses.
#[derive(Debug)]
struct SessionMap(RwLock<HashMap<String, String>>);

/// Maps the key set at the .well-known/jwks.json endpoint for your Auth0 domain.
#[derive(Serialize, Deserialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[derive(Serialize, Deserialize)]
struct JsonWebKey {
    alg: String,
    kty: String,
    // use is a Rust keyword, so we give the serializer special instructions.
    #[serde(rename = "use")]
    _use: String,
    x5c: Vec<String>,
    n: String,
    e: String,
    x5t: String,
}

/// For the state of the application, including the client secrets.
struct AppSettings {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth0_domain: String,
}

impl AppSettings {
    pub fn from_rocket_config(conf: &rocket::Config) -> Result<AppSettings, ConfigError> {
        let app_settings = AppSettings {
            client_id: String::from(conf.get_str("client_id")?),
            client_secret: String::from(conf.get_str("client_secret")?),
            redirect_uri: String::from(conf.get_str("redirect_uri")?),
            auth0_domain: String::from(conf.get_str("auth0_domain")?),
        };
        Ok(app_settings)
    }
}

#[derive(Debug)]
struct Email(String);

impl<'a, 'r> FromRequest<'a, 'r> for Email {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Email, ()> {
        let session_id: Option<String> = request
            .cookies()
            .get_private("session")
            .and_then(|cookie| cookie.value().parse().ok());

        match session_id {
            None => rocket::Outcome::Forward(()),
            Some(session_id) => {
                let session_map_state = State::<SessionMap>::from_request(request).unwrap();
                let session_map = session_map_state.0.read().unwrap();

                match session_map.get(&session_id) {
                    Some(email) => rocket::Outcome::Success(Email(email.clone())),
                    None => rocket::Outcome::Forward(()),
                }
            }
        }
    }
}
