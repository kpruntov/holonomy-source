// @trace TASK-123
use crate::ingestion::s3_client::{IngestionError, IngestionProvider};
use bytes::Bytes;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::metadata::ParquetMetaDataReader;
use std::ops::Range;

pub struct LocalFileProvider;

#[async_trait::async_trait]
impl IngestionProvider for LocalFileProvider {
    async fn fetch_byte_range(
        &self,
        url: &str,
        range: Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        let path = url.trim_start_matches("file://");
        let mut file =
            std::fs::File::open(path).map_err(|e| IngestionError::ParseFailed(e.to_string()))?;
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(range.start as u64))
            .map_err(|e| IngestionError::ParseFailed(e.to_string()))?;
        let mut buf = vec![0u8; range.end - range.start];
        file.read_exact(&mut buf)
            .map_err(|e| IngestionError::ParseFailed(e.to_string()))?;
        Ok(Bytes::from(buf))
    }

    async fn fetch_entire_file(&self, url: &str) -> Result<Bytes, IngestionError> {
        let path = url.trim_start_matches("file://");
        let bytes = std::fs::read(path).map_err(|e| IngestionError::ParseFailed(e.to_string()))?;
        Ok(Bytes::from(bytes))
    }

    async fn fetch_multiple_ranges(
        &self,
        url: &str,
        ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        let mut res = Vec::with_capacity(ranges.len());
        for r in ranges {
            res.push(self.fetch_byte_range(url, r).await?);
        }
        Ok(res)
    }

    async fn fetch_parquet_metadata(
        &self,
        url: &str,
        decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<ParquetMetaData, IngestionError> {
        let path = url.trim_start_matches("file://");
        let file =
            std::fs::File::open(path).map_err(|e| IngestionError::ParseFailed(e.to_string()))?;
        let mut builder = ParquetMetaDataReader::new();
        if let Some(props) = decryption_props {
            builder = builder.with_decryption_properties(Some(std::sync::Arc::new(props)));
        }
        Ok(builder
            .parse_and_finish(&file)
            .map_err(IngestionError::Parquet)?)
    }
}
