// @trace TASK-043
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_inspect_happy_path() {
    let mut cmd = Command::cargo_bin("holonomy-cli").unwrap();
    // Use the generated sample parquet file in holonomy-core/tests
    cmd.arg("inspect")
        .arg("../holonomy-core/tests/sample.parquet");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Logical Type (Arrow)"));
}

#[test]
fn test_inspect_missing_uri() {
    let mut cmd = Command::cargo_bin("holonomy-cli").unwrap();
    cmd.arg("inspect");
    cmd.assert().failure().stderr(predicate::str::contains(
        "the following required arguments were not provided:\n  <TARGET_URI>",
    ));
}

#[test]
fn test_inspect_generate_contract_stdout() {
    let mut cmd = Command::cargo_bin("holonomy-cli").unwrap();
    cmd.arg("inspect")
        .arg("../holonomy-core/tests/fixtures/base.parquet")
        .arg("--generate-contract");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "\"name\": \"../holonomy-core/tests/fixtures/base.parquet\"",
        ))
        .stdout(predicate::str::contains("\"type\": \"int64\""));
}

#[test]
fn test_inspect_generate_contract_file() {
    use tempfile::NamedTempFile;
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    let mut cmd = Command::cargo_bin("holonomy-cli").unwrap();
    cmd.arg("inspect")
        .arg("../holonomy-core/tests/fixtures/base.parquet")
        .arg("-g")
        .arg("-o")
        .arg(temp_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "Policy successfully written to {}",
            temp_path
        )));

    let content = std::fs::read_to_string(temp_path).unwrap();
    assert!(content.contains("\"name\": \"../holonomy-core/tests/fixtures/base.parquet\""));
    assert!(content.contains("\"type\": \"int64\""));
}

#[test]
fn test_inspect_generate_contract_directory() {
    let mut cmd = Command::cargo_bin("holonomy-cli").unwrap();
    cmd.arg("inspect")
        .arg("../holonomy-core/tests/fixtures/")
        .arg("--generate-contract");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "\"name\": \"../holonomy-core/tests/fixtures/\"",
        ))
        .stdout(predicate::str::contains("\"type\": \"int64\""));
}
