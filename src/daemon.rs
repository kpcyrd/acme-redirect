use crate::args::DaemonArgs;
use crate::config::Config;
use std::fs;
use crate::chall;
use crate::errors::*;
use crate::http_responses::REDIRECT;
use crate::http_responses::*;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use actix_web::{middleware, App, HttpServer};

fn get_host(req: &HttpRequest) -> Option<&str> {
    if let Some(host) = req.headers().get("Host") {
        if let Ok(host) = host.to_str() {
            Some(host)
        } else {
            None
        }
    } else {
        None
    }
}

#[inline]
fn bad_request() -> HttpResponse {
    HttpResponse::BadRequest().body(BAD_REQUEST)
}

#[inline]
fn not_found() -> HttpResponse {
    HttpResponse::NotFound().body(NOT_FOUND)
}

#[get("/{p:.*}")]
async fn redirect(req: HttpRequest) -> impl Responder {
    debug!("REQ: {:?}", req);

    let host = if let Some(host) = get_host(&req) {
        host
    } else {
        return bad_request();
    };
    debug!("host: {:?}", host);

    let path = req.uri();
    debug!("path: {:?}", path);

    let url = format!("https://{}{}", host, path);
    if url.chars().any(|c| c == '\n' || c == '\r') {
        return bad_request();
    }

    HttpResponse::MovedPermanently()
        .header("Location", url)
        .body(REDIRECT)
}

#[get("/.well-known/acme-challenge/{chall}")]
async fn acme(token: web::Path<String>, data: web::Data<Config>, req: HttpRequest) -> impl Responder {
    debug!("REQ: {:?}", req);
    info!("acme: {:?}", token);

    if !chall::valid_token(&token) {
        return bad_request();
    }

    let path = data.chall_dir.join(token.as_ref());
    debug!("Reading challenge proof: {:?}", path);
    if let Ok(proof) = fs::read(path) {
        HttpResponse::Ok().body(proof)
    } else {
        not_found()
    }
}

#[actix_rt::main]
pub async fn run(config: Config, args: DaemonArgs) -> Result<()> {
    HttpServer::new(move || {
        App::new()
            .data(config.clone())
            // enable logger
            .wrap(middleware::Logger::default())
            .service(acme)
            .service(redirect)
    })
    .bind(&args.bind_addr)
    .context("Failed to bind socket")?
    .run()
    .await
    .context("Failed to start http daemon")?;
    Ok(())
}
