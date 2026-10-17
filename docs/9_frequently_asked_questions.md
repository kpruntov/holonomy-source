# Frequently Asked Questions (FAQ)

## 1. How do I authenticate to AWS or GCP from my local machine?

Holonomy uses the industry standard for cloud authentication by integrating natively with your cloud provider's official CLI tools. **We strongly recommend against using `.env` files to store long-lived cloud credentials (like `AWS_ACCESS_KEY_ID` or GCP `.json` files) on your local machine.**

### Google Cloud (GCP)
If Holonomy is configured to use GCP KMS or Cloud Storage, you need to authenticate your local development environment using Application Default Credentials (ADC).

Run the following command in your terminal:
```bash
gcloud auth application-default login
```
This will open your browser and authenticate you. Holonomy will automatically detect the resulting credentials in `~/.config/gcloud/application_default_credentials.json` without any further configuration.

### Amazon Web Services (AWS)
If Holonomy is configured to use AWS KMS or S3, you should authenticate using AWS SSO.

Run the following command in your terminal:
```bash
aws sso login
```
Holonomy will automatically detect your active SSO session from `~/.aws/sso/cache`.

## 2. Why am I getting "Failed to initialize GCP KMS Adapter" or a Panic Exception?

If you see an error like this:
`PanicException: Failed to initialize GCP KMS Adapter. Are you logged in to GCP? Try running gcloud auth application-default login.`

This means Holonomy correctly read your `.holonomy.toml` configuration and determined that you are using GCP, but the underlying GCP SDK could not find your credentials. 
To fix this, simply run `gcloud auth application-default login` in your terminal and restart your Python kernel.

## 3. Why am I getting "environment variable is required" for Policy Bucket or KMS Key ID?

If you are running Holonomy inside a Jupyter notebook, make sure that you have a `.holonomy.toml` file located somewhere in that directory tree (either in the same folder or in any parent folder up to the root of the project). Holonomy will automatically crawl upwards from your current working directory to find the `.holonomy.toml` file to resolve these settings.
