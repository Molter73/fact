use std::{env, net::ToSocketAddrs};

use anyhow::Context;
use log::info;
use mongodb::Client;
use tonic::transport::Server;

use fact_compendium::FactServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact_core::init_log()?;
    info!("compendium starting up...");

    let db_client = Client::with_uri_str(env::var("FACT_COMPENDIUM_DB_URL").unwrap()).await?;

    db_client.database("fact");
    let server = FactServer { db_client };

    Server::builder()
        .add_service(fact_api::fact_service_server::FactServiceServer::new(
            server,
        ))
        .serve_with_shutdown(
            "0.0.0.0:8080"
                .to_socket_addrs()?
                .next()
                .context("No valid socket address found")?,
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await?;

    info!("compendium stopping...");
    Ok(())
}
