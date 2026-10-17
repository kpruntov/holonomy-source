// @trace TASK-077
use crate::manager::governance_manager::SchemaRegistryProvider;
use aws_sdk_s3::Client;

pub struct S3SchemaRegistryProvider {
    bucket: String,
    client: Client,
}

impl S3SchemaRegistryProvider {
    pub fn new(bucket: String, endpoint: Option<String>, region_name: Option<String>) -> Self {
        let do_async = async move {
            let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
            if let Some(ep) = endpoint {
                loader = loader.endpoint_url(ep);
            }
            if let Some(reg) = region_name {
                loader = loader.region(aws_config::Region::new(reg));
            }
            let sdk_config = loader.load().await;

            let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                .force_path_style(true)
                .build();

            Client::from_conf(s3_config)
        };

        let client = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(do_async))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(do_async)
        };

        Self { bucket, client }
    }
}

impl SchemaRegistryProvider for S3SchemaRegistryProvider {
    fn resolve_contract(&self, target: &str) -> Option<String> {
        use base64::Engine;
        let bucket = self.bucket.clone();
        let client = self.client.clone();

        let target_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(target.as_bytes());
        let key = format!("{}.json", target_b64);

        let do_async = async move {
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key(&key)
                .send()
                .await
                .ok()?;

            let data = resp.body.collect().await.ok()?.into_bytes();

            String::from_utf8(data.to_vec()).ok()
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(do_async))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            rt.block_on(do_async)
        }
    }
}
