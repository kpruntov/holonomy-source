// @trace TASK-118
use arrow::array::Int32Array;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use holonomy_core::manager::channel_writer::ChannelWriter;
use std::sync::Arc;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use bytes::Bytes;

#[tokio::test]
async fn test_channel_writer_serializes_multiple_batches() {
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
    
    // Create batches
    let batch1 = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int32Array::from(vec![1, 2, 3]))],
    ).unwrap();
    
    let batch2 = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int32Array::from(vec![4, 5, 6]))],
    ).unwrap();

    let (mut channel_writer, result_rx) = ChannelWriter::spawn(schema.clone(), None);
    
    // Send batches
    channel_writer.send(batch1.clone()).await.expect("Failed to send batch 1");
    channel_writer.send(batch2.clone()).await.expect("Failed to send batch 2");
    
    // Close the channel and wait for completion
    channel_writer.close().await.expect("Failed to close channel writer");
    
    // The background thread should finish and return the serialized bytes via a oneshot or similar.
    // For our ChannelWriter, let's assume `close()` waits for the join handle and returns the bytes
    // OR we pass a buffer to it, OR it returns the buffer via result_rx.
    // Let's design the API: result_rx is a oneshot::Receiver<Result<Vec<u8>, parquet::errors::ParquetError>>.
    let serialized_bytes = result_rx.await.expect("Channel closed").expect("Serialization failed");
    
    assert!(!serialized_bytes.is_empty());
    
    // Read back to verify
    let bytes = Bytes::from(serialized_bytes);
    let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes).unwrap().build().unwrap();
    
    let read_batch1 = reader.next().unwrap().unwrap();
    assert_eq!(read_batch1.num_rows(), 6); // By default, Parquet reader might return them together or separate
}
