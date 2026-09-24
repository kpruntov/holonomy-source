// @trace TASK-118
use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use tokio::sync::{mpsc, oneshot};

pub struct ChannelWriter {
    tx: mpsc::Sender<RecordBatch>,
}

impl ChannelWriter {
    /// Spawns a background thread on Tokio's blocking pool to serialize incoming RecordBatches to Parquet.
    /// The caller is responsible for passing `WriterProperties` configured with PME (Parquet Modular Encryption)
    /// metadata. Upon channel closure, `ArrowWriter::close()` will automatically flush the PME footer.
    /// Returns the ChannelWriter handle and a oneshot receiver that will yield the
    /// final serialized Parquet byte buffer.
    pub fn spawn(
        schema: SchemaRef,
        pme_props: Option<WriterProperties>,
    ) -> (Self, oneshot::Receiver<Result<Vec<u8>, ParquetError>>) {
        let (tx, mut rx) = mpsc::channel::<RecordBatch>(10);
        let (result_tx, result_rx) = oneshot::channel();

        tokio::task::spawn_blocking(move || {
            let mut buffer = Vec::new();
            let mut writer = match ArrowWriter::try_new(&mut buffer, schema, pme_props) {
                Ok(w) => w,
                Err(e) => {
                    if result_tx.send(Err(e)).is_err() {
                        eprintln!("Warning: Serialization thread failed to send error because receiver was dropped");
                    }
                    return;
                }
            };

            while let Some(batch) = rx.blocking_recv() {
                if let Err(e) = writer.write(&batch) {
                    if result_tx.send(Err(e)).is_err() {
                        eprintln!("Warning: Serialization thread failed to send write error because receiver was dropped");
                    }
                    return;
                }
            }

            match writer.close() {
                Ok(_) => {
                    if result_tx.send(Ok(buffer)).is_err() {
                        eprintln!("Warning: Serialization thread finished successfully but receiver was dropped");
                    }
                }
                Err(e) => {
                    if result_tx.send(Err(e)).is_err() {
                        eprintln!("Warning: Serialization thread failed to send close error because receiver was dropped");
                    }
                }
            }
        });

        (Self { tx }, result_rx)
    }

    /// Sends a RecordBatch to the background writer thread.
    pub async fn send(&mut self, batch: RecordBatch) -> Result<(), mpsc::error::SendError<RecordBatch>> {
        self.tx.send(batch).await
    }

    /// Explicitly closes the channel, allowing the background thread to flush the PME footer and finish.
    /// This is implicitly called when `ChannelWriter` is dropped, but calling it explicitly
    /// allows you to wait for the oneshot receiver.
    #[allow(clippy::result_unit_err)]
    pub async fn close(self) -> Result<(), ()> {
        drop(self.tx);
        Ok(())
    }
}
