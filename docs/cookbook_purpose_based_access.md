# Cookbook: Purpose-Based Access Control

A single dataset often serves multiple business units. However, different departments require radically different levels of access to the exact same data to fulfill their business purposes.

## The Challenge
If Marketing needs to send a promotional email, they require the `email` column in plaintext. If Data Science needs to build a churn model, they only need the `email` column hashed. 

Historically, data engineers solve this by duplicating the data: they run heavy ETL pipelines to create a `transactions_marketing` table and a `transactions_analytics_anonymized` table. This doubles your S3 storage costs and creates a massive maintenance burden.

## The Holonomy Solution: Purpose Bindings
Holonomy eliminates the need for data duplication. You store **one single encrypted Parquet file** in S3. Holonomy dynamically morphs the data at read-time based on the user's declared *Business Purpose*.

### The Policy Architecture
You define explicit mappings in your `holonomy_master_policy.json` using `purpose_bindings`. This ties a specific business intent to a specific access role.

```json
{
  "version": "1.0",
  "purpose_bindings": {
    "marketing-campaign": "marketer",
    "churn-modeling": "data-scientist"
  },
  "principals": {
    "marketer": {
      "global_row_filters": ["consent_promotional = true"],
      "selective_row_filters": [],
      "column_masks": { "email": "PLAINTEXT" },
      "tag_masks": {}
    },
    "data-scientist": {
      "global_row_filters": [],
      "selective_row_filters": [],
      "column_masks": { "email": "HASH" },
      "tag_masks": {}
    }
  }
}
```

### The Execution
When a user queries the dataset, they must declare their purpose (either via their JWT context or the Holonomy SDK). The Rust engine intercepts the read and dynamically applies the correct transformation.

```python
import holonomy

# The Data Scientist reads the SAME physical file in S3.
# The email column is dynamically HASHED in memory.
df_analytics = holonomy.read("s3://data-lake/users.parquet", purpose="churn-modeling")

# The Marketer reads the SAME physical file in S3.
# The email column is decrypted to PLAINTEXT, but the engine 
# forcibly drops any rows where consent_promotional = false.
df_marketing = holonomy.read("s3://data-lake/users.parquet", purpose="marketing-campaign")
```

## Business Impact
- **Massive Cost Savings**: You completely eliminate the compute costs of running anonymization ETL pipelines, and you halve your AWS S3 storage footprint by maintaining a single golden copy of the data.
- **Strict Compliance**: You mathematically prove to auditors that users can only access PII when operating under an approved, tightly scoped business purpose.
