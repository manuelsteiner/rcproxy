#[macro_use]
extern crate gotham_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

mod client;
mod options;
mod server;

use crate::client::HttpClient;
use futures::prelude::*;
use log::{debug, info, LevelFilter};
use options::OPT;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::from(OPT.log_level))
        .init();

    print_configuration();

    debug!("Setting up signal handlers.");

    let signals = signals();

    info!("Starting content proxy server.");
    info!("Listening for requests on {}", OPT.address);

    let server = gotham::init_server(&OPT.address, server::setup());

    future::select(server.boxed(), signals.boxed()).await;
    println!("Shutting down gracefully.");
}

fn print_configuration() {
    debug!("Configuration.");
    debug!("---");
    debug!("Address: {}", OPT.address);
    debug!("Server name: {}", OPT.server_name);
    if let Some(headers) = &OPT.headers {
        let mut header_string = String::new();
        let mut it = headers.iter().peekable();

        while let Some((key, value)) = it.next() {
            header_string.push_str(format!("\"{}: {}\"", key, value).as_str());
            if it.peek().is_some() {
                header_string.push_str(", ");
            }
        }
        debug!("Additional headers: {}", header_string);
    }
    if let Some(blacklist) = &OPT.blacklist_ip {
        debug!("Blacklist IP ranges: {}", &blacklist.join(", "));
    }
    if !OPT.filters_allow.is_empty() {
        debug!("Allow filter rules: {}", &OPT.filters_allow.join(", "));
    }
    if !OPT.filters_deny.is_empty() {
        debug!("Deny filter rules: {}", &OPT.filters_deny.join(", "));
    }
    debug!("Default filter rule: {}", OPT.filter_default);
    debug!("Key: {}", OPT.key);
    debug!("Allow HTTPS: {}", OPT.allow_https);
    debug!("Mimes: {}", OPT.mime.join(", "));
    debug!("Max size: {}", OPT.max_size.to_string());
    debug!("Max redirects: {}", OPT.max_redirects.to_string());
    debug!("Timeout: {}", OPT.timeout.to_string());
    if let Some(proxy) = &OPT.proxy {
        debug!("Proxy: {}", proxy);
    }
    if let (Some(username), Some(password)) = (&OPT.proxy_username, &OPT.proxy_password) {
        debug!("Proxy username: {}", username);
        debug!("Proxy password: {}", password);
    }
    debug!("Log level: {}", OPT.log_level.to_string());
    debug!("---");
}

fn signals() -> impl Future<Output = Result<(), ()>> {
    let sigterm = async {
        signal(SignalKind::terminate()).unwrap().recv().await;
        println!("Handling SIGTERM.");
        Ok::<(), ()>(())
    };

    let sigint = async {
        signal(SignalKind::interrupt()).unwrap().recv().await;
        println!("Handling SIGINT.");
        Ok::<(), ()>(())
    };

    async {
        future::select(sigterm.boxed(), sigint.boxed()).await;
        Ok::<(), ()>(())
    }
}
