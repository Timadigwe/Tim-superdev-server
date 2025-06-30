mod handlers;
mod types;

use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    
    HttpServer::new(|| {
        App::new()
            .service(handlers::generate_keypair)
            .service(handlers::create_token)
            .service(handlers::mint_token)
            .service(handlers::sign_message)
            .service(handlers::verify_message)
            .service(handlers::send_sol)
            .service(handlers::send_token)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
