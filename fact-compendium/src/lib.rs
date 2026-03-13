use std::net::ToSocketAddrs;

use anyhow::Context;
use log::info;
use tonic::transport::Server;

use crate::{db::FactDb, server::FactServer};

mod db;
mod server;

pub async fn run() -> anyhow::Result<()> {
    info!("compendium starting up...");

    let db = FactDb::new().await?;
    let server = FactServer { db };

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
