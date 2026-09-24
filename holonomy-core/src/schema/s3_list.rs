// @trace TASK-051
use quick_xml::Reader;
use quick_xml::events::Event;
use reqwest::Client;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum S3ListError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("XML parsing error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
}

pub async fn list_s3_objects(
    client: &Client,
    uri: &str,
    max_keys: usize,
    endpoint_override: Option<&str>,
) -> Result<Vec<String>, S3ListError> {
    if !uri.starts_with("s3://") && !uri.starts_with("r2://") {
        return Err(S3ListError::InvalidUri(
            "Must start with s3:// or r2://".to_string(),
        ));
    }

    let is_r2 = uri.starts_with("r2://");
    let scheme = if is_r2 { "r2://" } else { "s3://" };
    let trimmed = uri.strip_prefix(scheme).unwrap();
    let parts: Vec<&str> = trimmed.splitn(2, '/').collect();
    let bucket = parts[0];
    let prefix = if parts.len() > 1 { parts[1] } else { "" };

    let mut continuation_token: Option<String> = None;
    let mut keys = Vec::new();

    loop {
        let mut url = if let Some(ep) = endpoint_override {
            format!("{}/?list-type=2&prefix={}", ep, prefix)
        } else if is_r2 {
            format!(
                "https://{}.r2.cloudflarestorage.com/?list-type=2&prefix={}",
                bucket, prefix
            )
        } else {
            format!(
                "https://{}.s3.amazonaws.com/?list-type=2&prefix={}",
                bucket, prefix
            )
        };
        if let Some(token) = &continuation_token {
            url.push_str(&format!("&continuation-token={}", token));
        }

        let resp = client.get(&url).send().await?.text().await?;

        let mut reader = Reader::from_str(&resp);
        reader.trim_text(true);

        let mut buf = Vec::new();
        let mut inside_key = false;
        let mut inside_next_token = false;
        let mut inside_is_truncated = false;
        let mut is_truncated = false;
        let mut current_next_token = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"Key" => inside_key = true,
                    b"IsTruncated" => inside_is_truncated = true,
                    b"NextContinuationToken" => inside_next_token = true,
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if inside_key {
                        let key_text = e.unescape().unwrap().into_owned();
                        if key_text.ends_with(".parquet") {
                            keys.push(format!("{}{}/{}", scheme, bucket, key_text));
                        }
                    } else if inside_next_token {
                        current_next_token = Some(e.unescape().unwrap().into_owned());
                    } else if inside_is_truncated {
                        let text = e.unescape().unwrap().into_owned();
                        if text == "true" {
                            is_truncated = true;
                        }
                    }
                }
                Ok(Event::End(ref e)) => match e.name().as_ref() {
                    b"Key" => inside_key = false,
                    b"NextContinuationToken" => inside_next_token = false,
                    b"IsTruncated" => inside_is_truncated = false,
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(S3ListError::Xml(e)),
                _ => {}
            }
            buf.clear();
            if keys.len() >= max_keys {
                return Ok(keys);
            }
        }

        if is_truncated && current_next_token.is_some() {
            continuation_token = current_next_token;
        } else {
            break;
        }
    }

    Ok(keys)
}
