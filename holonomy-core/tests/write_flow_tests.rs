// @trace TASK-016
use arrow::array::{Int32Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use holonomy_core::crypto::pme_encrypt::{PmeEncryptor, S3MultipartUploader};
use mockito::Server;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::encryption::decrypt::FileDecryptionProperties;
use std::sync::Arc;

#[tokio::test]
async fn test_end_to_end_write_flow_with_pme() {
    let dek = "1234567890123456".to_string(); // 16 bytes for AES
    let wrapped_dek = b"kms_wrapped:MTIzNDU2Nzg5MDEyMzQ1Ng==".to_vec();
    let mut column_deks = std::collections::HashMap::new();
    column_deks.insert(
        "name".to_string(),
        zeroize::Zeroizing::new(dek.as_bytes().to_vec()),
    );
    let mut wrapped_column_deks = std::collections::HashMap::new();
    wrapped_column_deks.insert("name".to_string(), b"kms_wrapped_col_dek".to_vec());
    let encryptor = PmeEncryptor::new(
        zeroize::Zeroizing::new(dek.as_bytes().to_vec()),
        wrapped_dek,
        column_deks,
        wrapped_column_deks,
    );
    // Specify that we want to encrypt the "name" column
    let props = encryptor.get_writer_properties_builder().build();

    // Create some data
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["Alice", "Bob", "Charlie"])),
        ],
    )
    .unwrap();

    // Write encrypted Parquet
    let mut buf = Vec::new();
    {
        let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }
    let encrypted_bytes = Bytes::from(buf);

    // Attempt to read without decryption properties - should fail to read actual column data
    // Because we use plaintext footers, the builder will succeed, but iterating the batches will fail
    let read_result = ParquetRecordBatchReaderBuilder::try_new(encrypted_bytes.clone());
    assert!(
        read_result.is_ok(),
        "Builder should succeed because footer is plaintext"
    );
    let mut reader = read_result.unwrap().build().unwrap();
    let batch_res = reader.next();
    assert!(
        batch_res.is_some() && batch_res.unwrap().is_err(),
        "Standard tools should fail to read the encrypted column data without DEK"
    );

    // Attempt to read with decryption properties - should succeed
    let dec_props = FileDecryptionProperties::builder(dek.clone().into_bytes())
        .with_column_key("name", dek.clone().into_bytes())
        .build()
        .unwrap();
    let reader_options = ArrowReaderOptions::new().with_file_decryption_properties(dec_props);
    let reader_builder_res = ParquetRecordBatchReaderBuilder::try_new_with_options(
        encrypted_bytes.clone(),
        reader_options,
    );
    assert!(
        reader_builder_res.is_ok(),
        "Should be able to read with DEK"
    );
    let _reader = reader_builder_res.unwrap().build().unwrap();

    // Mock S3 multipart upload endpoints
    let mut server = Server::new_async().await;

    // aws-sdk-s3 multipart endpoints usually look like:
    // Create: POST /bucket/key?uploads
    // UploadPart: PUT /bucket/key?partNumber=1&uploadId=...
    // Complete: POST /bucket/key?uploadId=...
    let mock_create = server.mock("POST", mockito::Matcher::Regex(r".*\?uploads$".to_string()))
        .with_status(200)
        .with_body(r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><UploadId>mock-upload-id</UploadId></InitiateMultipartUploadResult>"#)
        .create_async().await;

    let mock_upload_part = server
        .mock(
            "PUT",
            mockito::Matcher::Regex(r".*partNumber=.*".to_string()),
        )
        .with_status(200)
        .with_header("ETag", "\"mock_etag\"")
        .create_async()
        .await;

    let mock_complete = server.mock("POST", mockito::Matcher::Regex(r".*uploadId=mock-upload-id$".to_string()))
        .with_status(200)
        .with_body(r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult></CompleteMultipartUploadResult>"#)
        .create_async().await;

    let uploader = S3MultipartUploader::new(
        "test-bucket".to_string(),
        Some(server.url()),
        Some("us-east-1".to_string()),
        None,
        Some(("mock".to_string(), "mock".to_string())),
    )
    .await;
    let result = uploader
        .upload_file("test.parquet", encrypted_bytes.to_vec())
        .await;

    if let Err(e) = &result {
        println!("Upload error: {:?}", e);
    }
    assert!(result.is_ok());

    mock_create.assert_async().await;
    mock_upload_part.assert_async().await;
    mock_complete.assert_async().await;
}
