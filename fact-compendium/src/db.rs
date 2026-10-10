use std::env;

use fact_core::event::{
    Event, EventData, ProcessData, ProcessExecData, ProcessExitData, ProcessForkData,
    process::Process,
};
use log::info;
use mongodb::{Collection, IndexModel, bson::doc, options::IndexOptions};

#[derive(Debug)]
pub(crate) struct FactDb {
    processes: Collection<Process>,
    events: Collection<Event>,
}

impl FactDb {
    pub(crate) async fn new() -> anyhow::Result<Self> {
        info!("Initializing DB client...");
        let client = mongodb::Client::with_uri_str(env::var("FACT_COMPENDIUM_DB_URL")?).await?;
        let db = client.database("fact");

        info!("Creating tables and indexes");
        db.create_collection("events").await?;
        let events = db.collection("events");

        db.create_collection("processes").await?;
        let processes = db.collection("processes");
        processes
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "hostname": 1, "upid": 1})
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        processes
            .create_index(
                IndexModel::builder()
                    .keys(doc! {"hostname":1,"parent_upid": 1})
                    .build(),
            )
            .await?;

        info!("DB init done");
        Ok(FactDb { processes, events })
    }

    pub(crate) async fn insert_event(&self, event: Event) -> anyhow::Result<()> {
        if !matches!(event.data, EventData::Process(ProcessData::Proc(_))) {
            self.events.insert_one(&event).await?;
        }

        if let EventData::Process(proc) = event.data {
            match proc {
                ProcessData::Fork(ProcessForkData { child: proc })
                | ProcessData::Exec(ProcessExecData(proc))
                | ProcessData::Exit(ProcessExitData(proc))
                | ProcessData::Proc(proc) => {
                    self.processes
                        .replace_one(doc! {"upid": proc.upid as i64}, proc)
                        .upsert(true)
                        .await?;
                }
            };
        }

        Ok(())
    }
}
