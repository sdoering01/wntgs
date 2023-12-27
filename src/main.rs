mod repository;
mod web;

use web::App;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    App::new().await?.serve().await
}
