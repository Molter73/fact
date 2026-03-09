use anyhow::Context;

fn main() -> anyhow::Result<()> {
    tonic_prost_build::configure()
        .compile_protos(&["proto/fact-api/fact_iservice.proto"], &["proto"])
        .context("Failed to compile protos")?;
    Ok(())
}
