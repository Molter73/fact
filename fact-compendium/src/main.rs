#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact_core::init_log()?;

    fact_compendium::run().await
}
