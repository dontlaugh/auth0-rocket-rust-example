#![feature(plugin)]
#![plugin(rocket_codegen)]
#![allow(warnings)] // dev only
#![feature(proc_macro)]
#![feature(proc_macro_non_items)]
#![feature(custom_derive)]

#[cfg(feature="ring-crypto")]
extern crate jsonwebtoken as jwt;
#[cfg(feature="default")]
extern crate frank_jwt as jwt;

extern crate maud;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_codegen;
extern crate url;
extern crate base64;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use jwt::{decode, encode, Algorithm };

use serde::Serialize;
use serde_json::ser::to_vec;
use std::io::Read;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use maud::{html, Markup};
use reqwest::header::ContentType;
use reqwest::mime::APPLICATION_JSON;
use rocket::fairing::AdHoc;
use rocket::http::uri::URI;
use rocket::http::{Cookie, Cookies, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{status, Redirect};
use rocket::State;
use url::Url;

use std::str::FromStr;

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

    // It is time to decode the JWT
    // https://auth0.com/docs/tokens/id-token#verify-the-signature
    write_file("fetched_token.txt", &resp.id_token.as_bytes());

    let sec = read_file("coleman_pubkey.pem").expect("file reading failed");
    //let based = base64::encode(&sec); // DIDNT WORK

    // secret from jwks endpoint:
//    let jwt_header = decode_header(&resp.id_token).expect("decode jwt header");
//    println!("header: {:?}", jwt_header);
    let (foo, baz) = decode(
        &resp.id_token,
        //based.as_bytes(),
        &String::from_utf8(sec).expect("from_utf8 failed"),
        Algorithm::RS256,
    ).expect("decoding JWT should work, people");

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
    id_token: String, // JWT type here?
    token_type: String,
}

/// Maps session keys to email addresses.
#[derive(Debug)]
struct SessionMap(RwLock<HashMap<String, String>>);

/// For the state of the application, including the client secrets.
struct AppSettings {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth0_domain: String,
}

impl AppSettings {
    pub fn from_rocket_config(
        conf: &rocket::Config,
    ) -> Result<AppSettings, rocket::config::ConfigError> {
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
