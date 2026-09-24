// @trace TASK-046
use holonomy_core::schema::drift::check_local_directory_drift;
#[tokio::test]
async fn test_drift_detection() {
    let dir_path = "tests/fixtures";

    // We expect the dir to contain base.parquet and mutated.parquet
    // which have different schemas.
    // check_local_directory_drift sorts files, so base.parquet is first.
    // When it encounters mutated.parquet, it should detect drift.

    let result = check_local_directory_drift(dir_path).await;
    assert!(result.is_ok());
    assert!(
        result.unwrap(),
        "Drift should be detected between base and mutated parquet files"
    );
}
