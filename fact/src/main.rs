use fact::config::FactConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact_core::init_log()?;
    let config = FactConfig::new()?;

    fact::run(config).await
}
