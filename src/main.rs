#![feature(plugin)]
#![plugin(rocket_codegen)]
#![allow(warnings)] // dev only
#![feature(proc_macro)]

extern crate rocket;
extern crate rocket_codegen;
extern crate maud;
extern crate libloading;

#[macro_use]
extern crate serde_derive;
extern crate serde;

use libloading::{Library, Symbol};

use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use serde::{Serialize};

use maud::{html, Markup};
use rocket::response::status;

fn main() {
    let routes = get_routes();
    rocket::ignite().mount("/", routes).launch();
}

fn get_routes() -> Vec<rocket::Route> {
    routes![index]
}

#[get("/")]
fn index() -> Markup {

    let lib;
    let partial: Symbol<extern fn() -> Markup>;
    unsafe {
        lib = Library::new("partial/target/debug/libpartial.so").unwrap();
        partial = lib.get(b"partial\0").unwrap();
    }

    html!{
       body {
           h1 "hello world"
           (partial())
       }
    }

}
