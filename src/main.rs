#![feature(plugin)]
#![plugin(rocket_codegen)]
#![allow(warnings)] // dev only
#![feature(proc_macro)]
#![feature(proc_macro_non_items)]
#![feature(custom_derive)]

extern crate maud;
extern crate rocket;
extern crate rocket_codegen;
extern crate reqwest;
extern crate url;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::path::{Path, PathBuf};
use serde::Serialize;
use serde_json::ser::to_vec;

use maud::{html, Markup};
use rocket::response::status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::fairing::AdHoc;

use url::Url;
use rocket::http::uri::URI;

use std::str::FromStr;

fn main() {
    let sessions = SessionMap(RwLock::new(HashMap::new()));
    let routes = get_routes();
    rocket::ignite()
        .mount("/", routes)
        .manage(sessions)
        .attach(AdHoc::on_attach(|rocket| {
            let app_settings = AppSettings {
                client_id: String::from(rocket.config().get_str("client_id").unwrap()),
                client_secret: String::from(rocket.config().get_str("client_secret").unwrap()),
                redirect_uri: String::from(rocket.config().get_str("redirect_uri").unwrap()),
                auth0_domain: String::from(rocket.config().get_str("auth0_domain").unwrap()),
            };
            Ok(rocket.manage(app_settings))
        }))
        .launch();
}

fn get_routes() -> Vec<rocket::Route> {
    routes![index, login, login_code]
}

// deprecated in favor of full-on proc macro stuff
// https://github.com/rust-lang/rust/issues/29644#issuecomment-359094330
#[derive(FromForm)]
struct CodeAndState {
    code: String,
    state: String,
}

#[get("/")]
fn index() -> Markup {
    html!{
       body {
           h1 "hello world"
           a href="/login" "Login!"
       }
    }
}

#[get("/protected")]
fn protected_authorized(email: Email) -> Result<String, Status> {
    Ok(String::from_str("great").unwrap())
}

#[get("/protected", rank = 2)]
fn protected_unauthorized() -> Redirect {
    Redirect::to("/")
}

/// Login page!
#[get("/login")]
fn login(settings: State<AppSettings>) -> Redirect {
    let data = TokenRequest {
        grant_type: String::from_str("authorization_code").unwrap(),
        client_id: settings.client_id.clone(),
        client_secret: settings.client_secret.clone(),
        //code: code.code,
        redirect_uri: settings.redirect_uri.clone(),
    };
    Redirect::to(&data.to_url())
}



/// Login callback. Auth0 sends a request to this endpoint. In this function,
/// we extract the "code" and "state" parameters, ensuring that state matches
/// exactly the string we passed to Auth0's /authorize endpoint. Then we can
/// use send code the /oauth/token endpoint in exchange for an access token.
#[get("/callback?<code>")]
fn login_code(code: CodeAndState, settings: State<AppSettings>) -> Result<String, Status> {
    use reqwest::header::ContentType;
    // There may be a better way to post this.
    let data = TokenRequestWithCode {
        grant_type: String::from_str("authorization_code").unwrap(),
        client_id: settings.client_id.clone(),
        client_secret: settings.client_secret.clone(),
        code: code.code.clone(),
        redirect_uri: settings.redirect_uri.clone(),
    };
    // TODO check state
    //let resp = reqwest::get(&data.to_url()).expect("get failed to token endpoint");
    
    //let encoded_url = &URI::percent_encode(&data.redirect_uri).to_string();
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", code.code.as_str());
    params.insert("redirect_uri", &data.redirect_uri);
    params.insert("client_id", &data.client_id);
    params.insert("client_secret", &data.client_secret);
    println!("params! {:?}", params);
    let token_url = "https://coleman.auth0.com/oauth/token";
    let resp = reqwest::Client::new()
        .post(token_url.clone()).header(ContentType(reqwest::mime::APPLICATION_JSON))
        .body(to_vec(&params).expect("could not serialize hashmap")).send().expect("POST REQUEST");
    println!("got response: {:?}", resp);

    Ok(String::from("Thanks"))
}

struct CodeRequest {}

struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    //code: String,
    redirect_uri: String,
}

impl TokenRequest {
    pub fn to_url(&self) -> String {
        let s = format!(
            "https://coleman.auth0.com/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&state=offthedamnchain",
             self.client_id, URI::percent_encode(&self.redirect_uri));
        s
    }
}

struct TokenRequestWithCode {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

impl TokenRequestWithCode {
    pub fn to_url(&self) -> String {
        let s = format!(
            "https://coleman.auth0.com/oauth/token?client_id={}&redirect_uri={}&client_secret={}&code={}",
             self.client_id, URI::percent_encode(&self.redirect_uri), self.client_secret, self.code);
        s
    }
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
