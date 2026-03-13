use fact_core::event::Event;
use log::warn;
use tokio_stream::StreamExt;

use crate::db::FactDb;

#[derive(Debug)]
pub(crate) struct FactServer {
    pub(crate) db: FactDb,
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
                    if let Err(e) = self.db.insert_event(event).await {
                        warn!("Error: {e:#?}");
                        return Err(tonic::Status::new(tonic::Code::Internal, e.to_string()));
                    }
                }
                Err(e) => {
                    warn!("Error: {e:#?}");
                    return Err(tonic::Status::new(tonic::Code::Internal, e.to_string()));
                }
            }
        }
        Ok(tonic::Response::new(()))
    }
}
