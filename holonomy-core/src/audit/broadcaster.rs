// @trace TASK-019
use crate::audit::ring_buffer::AuditRingBuffer;
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Clone)]
pub enum SinkConfig {
    Stdout,
    LocalFile(String),
    SaaS(String, Option<String>),
}

pub struct AuditBroadcaster {
    buffer: Arc<AuditRingBuffer>,
    sink: SinkConfig,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
}

impl AuditBroadcaster {
    pub fn new(
        buffer: Arc<AuditRingBuffer>,
        sink: SinkConfig,
        batch_size: usize,
        flush_interval: Duration,
        max_retries: u32,
    ) -> Self {
        Self {
            buffer,
            sink,
            batch_size,
            flush_interval,
            max_retries,
        }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    async fn run(&self) {
        let client = reqwest::Client::new();

        #[derive(serde::Serialize)]
        struct EnrichedAuditEvent<'a> {
            #[serde(flatten)]
            event: &'a crate::audit::ring_buffer::AuditEvent,
            license_status: &'static str,
        }

        loop {
            let mut batch = Vec::new();
            while let Some(event) = self.buffer.pop() {
                batch.push(event);
                if batch.len() >= self.batch_size {
                    break;
                }
            }

            if batch.is_empty() {
                tokio::time::sleep(self.flush_interval).await;
                continue;
            }

            let license_status = if crate::manager::license_manager::is_license_valid() {
                "VALID"
            } else {
                "UNLICENSED"
            };

            let enriched_batch: Vec<_> = batch.iter().map(|event| EnrichedAuditEvent {
                event,
                license_status,
            }).collect();

            let body_json = match serde_json::to_string(&enriched_batch) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Failed to serialize audit batch: {}", e);
                    continue;
                }
            };

            let (endpoint, auth_token) = match &self.sink {
                SinkConfig::SaaS(url, token) => (url.clone(), token.clone()),
                SinkConfig::Stdout => {
                    println!("AUDIT EVENT BATCH: {}", body_json);
                    continue;
                }
                SinkConfig::LocalFile(path) => {
                    use tokio::io::AsyncWriteExt;
                    match tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .await
                    {
                        Ok(mut file) => {
                            if let Err(e) =
                                file.write_all(format!("{}\n", body_json).as_bytes()).await
                            {
                                eprintln!("Failed to write to local audit file: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to open local audit file: {}", e);
                        }
                    }
                    continue;
                }
            };

            let mut retries = 0;
            let mut backoff = Duration::from_millis(100);

            loop {
                let mut req = client
                    .post(&endpoint)
                    .header("content-type", "application/json")
                    .body(body_json.clone());

                if let Some(token) = &auth_token {
                    req = req.bearer_auth(token);
                }

                let res = req.send().await;

                match res {
                    Ok(response) if response.status().is_success() => {
                        break;
                    }
                    _ => {
                        retries += 1;
                        if retries > self.max_retries {
                            eprintln!(
                                "AuditBroadcaster: Dropping batch after {} retries",
                                self.max_retries
                            );
                            break;
                        }
                        tokio::time::sleep(backoff).await;
                        backoff *= 2; // exponential backoff
                    }
                }
            }
        }
    }
}
