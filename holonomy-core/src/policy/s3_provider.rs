// @trace TASK-076
use crate::manager::policy_manager::{PolicyError, PolicyProvider};
use crate::policy::manifest::PolicyLevel;
use aws_sdk_s3::Client;

pub struct S3PolicyProvider {
    bucket: String,
    client: Client,
}

impl S3PolicyProvider {
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

impl PolicyProvider for S3PolicyProvider {
    fn discover_policies(&self, _target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        let bucket = self.bucket.clone();
        let client = self.client.clone();

        let do_async = async move {
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key("holonomy_master_policy.json")
                .send()
                .await
                .map_err(|e| {
                    PolicyError::DiscoveryFailed(format!("S3 get_object failed: {:?}", e))
                })?;

            let data = resp
                .body
                .collect()
                .await
                .map_err(|e| {
                    PolicyError::DiscoveryFailed(format!("Failed to read S3 body: {:?}", e))
                })?
                .into_bytes();

            let content = String::from_utf8(data.to_vec())
                .map_err(|e| PolicyError::ParseError(format!("Invalid UTF-8 in policy: {}", e)))?;

            Ok(vec![(PolicyLevel::Global, content)])
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(do_async))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| PolicyError::ParseError(format!("Runtime error: {}", e)))?;
            rt.block_on(do_async)
        }
    }
}
