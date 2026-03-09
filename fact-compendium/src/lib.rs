use fact_core::event::Event;
use log::warn;
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct FactServer {
    pub db_client: mongodb::Client,
}

#[tonic::async_trait]
impl fact_api::fact_service_server::FactService for FactServer {
    async fn communicate(
        &self,
        request: tonic::Request<tonic::Streaming<fact_api::FactMsg>>,
    ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
        let mut stream = request.into_inner();
        while let Some(res) = stream.next().await {
            match res {
                Ok(event) => {
                    let event = Event::from(event);
                    let db = self.db_client.database("fact");
                    if event.is_file_event() {
                        if let Err(e) = db.collection("file").insert_one(event).await {
                            return Err(tonic::Status::new(tonic::Code::Internal, e.to_string()));
                        }
                    } else if let Err(e) = db.collection("process").insert_one(event).await {
                        return Err(tonic::Status::new(tonic::Code::Internal, e.to_string()));
                    }
                }
                Err(e) => {
                    warn!("Error: {e:#?}");
                    break;
                }
            }
        }
        Ok(tonic::Response::new(()))
    }
}
