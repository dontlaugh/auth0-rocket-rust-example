#![feature(plugin)]
#![plugin(rocket_codegen)]
#![allow(warnings)] // dev only
#![feature(proc_macro)]
#![feature(proc_macro_non_items)]
#![feature(custom_derive)]

extern crate maud;
extern crate rocket;
extern crate rocket_codegen;

#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::path::{Path, PathBuf};
use serde::Serialize;

use maud::{html, Markup};
use rocket::response::status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::fairing::AdHoc;


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
    routes![index]
}

// deprecated in favor of full-on proc macro stuff
// https://github.com/rust-lang/rust/issues/29644#issuecomment-359094330
#[derive(FromForm)]
struct Code {
    code: String
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
    Redirect::to("/login")
}

/// Login page!
#[get("/login")]
fn login() -> Markup {
    html!{
        body {
            div class="login-form" {
            }
        }
    }
}



/// Login callback.
#[get("/login?<code>")]
fn login_code(
    code: Code,
    settings: State<AppSettings>,
) -> Result<String, Status> {
    // There may be a better way to post this.
    let data = TokenRequest {
        grant_type: String::from_str("authorization_code").unwrap(),
        client_id: settings.client_id.clone(),
        client_secret: settings.client_secret.clone(),
        code: code.code,
        redirect_uri: settings.redirect_uri.clone(),
    };

    Ok(String::from("Thanks"))
}

struct CodeRequest {


}


struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
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
