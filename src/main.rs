mod handlers;
mod types;

use actix_web::{App, HttpServer};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Get port from environment variable (for Render) or default to 8080
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("0.0.0.0:{}", port);
    
    println!(" Starting Tim's Solana HTTP Server...");
    println!(" Server will be available at: http://0.0.0.0:{}", port);
    println!("Server starting...");
    println!(" Tim's Solana HTTP Server is running on port {}!", port);
    println!(" Ready to accept requests...");
    
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
    .bind(&bind_address)?
    .run()
    .await
}
