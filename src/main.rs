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

extern crate base64;
extern crate bincode;
extern crate chrono;
extern crate crypto_hash;
extern crate maud;
extern crate openssl;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_codegen;
extern crate sled;
extern crate url;
extern crate x509_parser;

#[macro_use]
extern crate keyz;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use crypto_hash::hex_digest;
use crypto_hash::Algorithm as HashAlgorithm;

#[cfg(feature = "default")]
use frank_jwt::{decode, encode, Algorithm};

#[cfg(feature = "ring-crypto")]
use jsonwebtoken::{decode, decode_header, Algorithm, TokenData, Validation};

use serde::Serialize;
use serde_json::ser::to_vec;
use serde_json::{from_value, Value};

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use bincode::{deserialize, serialize};
use chrono::Utc;
use keyz::Key;
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

type DB = Arc<sled::Tree>;

fn main() {
    let routes = get_routes();
    let db: DB = {
        let config = sled::ConfigBuilder::new().path(".data").build();
        Arc::new(sled::Tree::start(config).unwrap())
    };
    rocket::ignite()
        .mount("/", routes)
        .manage(db)
        .attach(AdHoc::on_attach(|rocket| {
            let conf = rocket.config().clone();
            let app_settings = AppSettings::from_rocket_config(&conf).expect("configuration error");
            {
                // a call to state() borrows the rocket instance, but we can
                // introduce a lexical scope to limit our temporary borrow.
                let db = rocket.state::<DB>().unwrap();
                populate_certs(db, &app_settings.auth0_domain);
            }

            Ok(rocket.manage(app_settings))
        }))
        .launch();
}

fn populate_certs(db: &DB, auth0_domain: &str) {
    let client = reqwest::Client::new();
    let cert_endpoint = format!("https://{}/pem", auth0_domain);
    let mut pem_cert: String = client
        .get(Url::from_str(&cert_endpoint).unwrap())
        .send()
        .unwrap()
        .text()
        .unwrap();
    // openssl stuff
    // transform cert into X509 struct
    use openssl::x509::X509;
    let cert = X509::from_pem(pem_cert.as_bytes()).expect("x509 parse failed");
    let pk = cert.public_key().unwrap();
    // extract public keys and cert in pem and der
    let pem_pk = pk.public_key_to_pem().unwrap();
    let der_pk = pk.public_key_to_der().unwrap();
    let der_cert = cert.to_der().unwrap();
    // save as bytes to database
    db.set(b"jwt_pub_key_pem".to_vec(), pem_pk);
    db.set(b"jwt_pub_key_der".to_vec(), der_pk);
    db.set(b"jwt_cert_der".to_vec(), der_cert);
}

fn get_routes() -> Vec<rocket::Route> {
    routes![login, auth0_redirect, auth0_callback, home, guarded_home]
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
fn login() -> Markup {
    html!{
       body {
           h1 "hello world"
           a href="/auth0" "Login With Auth0!"
       }
    }
}

#[get("/")]
fn home(user: User) -> Result<String, Status> {
    Ok(String::from_str("great").unwrap())
}

#[get("/", rank = 2)]
fn guarded_home() -> Redirect {
    Redirect::to("/login")
}

/// This route reads settings from our application state and redirects to our
/// configured Auth0 login page. If our user's login is successful, Auth0 will
/// redirect them back to /callback with "code" and "state" as query params.
#[get("/auth0")]
fn auth0_redirect(mut cookies: Cookies, settings: State<AppSettings>) -> Redirect {
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
    db: State<DB>,
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

    #[cfg(feature = "default")]
    {
        let pk = db.get(b"jwt_pub_key_pem")
            .map_err(|_| Status::Unauthorized)?
            .expect("public key not in database");
        let (_, payload) = decode(
            &resp.id_token,
            &String::from_utf8(pk).expect("from_utf8 failed"),
            Algorithm::RS256,
        ).map_err(|_| Status::Unauthorized)?;
        let now = Utc::now().timestamp();
        let mut expiration = 0;
        if let Some(exp) = payload.get("exp") {
            let val = from_value::<i64>(exp.clone()).map_err(|_| Status::Unauthorized)?;
            if val < now {
                return Err(Status::Unauthorized);
            }
            expiration = val;
        }

        let user_id = (|| {
            match (payload.get("user_id"), payload.get("email")) {
                (Some(user_id), Some(email)) =>  {
                    println!("payload has email:{}, user_id: {}", email, user_id);
                    let user_key = make_key!("users/", user_id.to_string());
                    match db.get(&user_key.0) {
                        Ok(None) => {
                            // create if does not exist.
                            println!("create user if does not exist!");
                            let user = User{email: email.to_string(), user_id: user_id.to_string()};
                            let encoded_user = serialize(&user).map_err(|_| Status::Unauthorized)?;
                            db.set(user_key.0, encoded_user);
                            Ok(user.user_id)
                        },
                        Ok(Some(user_bytes)) => {
                            println!("found user bytes!!!!");
                            Ok(user_id.to_string())
                        },
                        _ => Err(Status::Unauthorized)
                    }
                    //Ok((user_id.to_string(), email.to_string()))
                },
                _ => Err(Status::Unauthorized)
            }
        })()?;

        let jwt = &resp.id_token.clone();
        let hashed_jwt = hex_digest(HashAlgorithm::SHA256, jwt.as_bytes());
        let new_session = Session{user_id: user_id, expires: expiration};
        let encoded_session = serialize(&new_session).map_err(|_| Status::Unauthorized)?;
        let session_key = make_key!("sessions", "/", hashed_jwt.clone());
        db.set(session_key.0, encoded_session);
        cookies.add(Cookie::new("session", hashed_jwt));
    }

    // This feature doesn't work right now, because (I think) we need the
    // private key.
    #[cfg(feature = "ring-crypto")]
    {
        let pk = db.get(b"jwt_pub_key_der")
            .expect("jwt_cert_der missing")
            .unwrap();
        println!("ring-crypto config");
        let headers = decode_header(&resp.id_token).expect("could not decode headers");
        let token_data: TokenData<HashMap<String, String>> =
            decode(&resp.id_token, &pk, &Validation::new(headers.alg)).unwrap();
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

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    user_id: String,
    expires: i64,
}

impl Session {
    pub fn expired(&self) -> bool {
        let now = Utc::now().timestamp();
        self.expires <= now 
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> Outcome<User, ()> {
        let session_id: Option<String> = request
            .cookies()
            .get("session")
            .and_then(|cookie| cookie.value().parse().ok());
        // get session
        println!("session ID: {:?}", session_id);
        match session_id {
            None => rocket::Outcome::Forward(()),
            Some(session_id) => {
                let db = State::<DB>::from_request(request).unwrap();
                let session_key = make_key!("sessions", "/", session_id);
                println!("session key! {:?}", session_key);
                match db.get(&session_key.0) {
                    Ok(Some(sess)) => {
                        // deserialize
                        let sess: Session =
                            deserialize(&sess).expect("could not deserialize session");
                        println!("found Session {:?}", sess);
                        // check expiration
                        if sess.expired() {
                            println!("expired?!");
                            return rocket::Outcome::Forward(());
                        }
                        // get the user
                        let user_key = make_key!("users/", sess.user_id);
                        println!("user key! {:?}", user_key);
                        match db.get(&user_key.0) {
                            Ok(Some(user)) => {
                                println!("Ok(Some(user)) matched");
                                let user: User =
                                    deserialize(&user).expect("could not deserialize user");
                                rocket::Outcome::Success(user)
                            }
                            _ => rocket::Outcome::Forward(()),
                        }
                    }
                    _ => rocket::Outcome::Forward(()),
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    user_id: String,
    email: String,
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
