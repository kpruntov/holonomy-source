// @trace TASK-045
use parquet::file::metadata::ParquetMetaData;

pub struct ColumnInfo {
    pub name: String,
    pub physical_type: String,
    pub logical_type: String,
}

pub fn extract_columns(metadata: &ParquetMetaData) -> Vec<ColumnInfo> {
    let schema_descr = metadata.file_metadata().schema_descr();
    schema_descr
        .columns()
        .iter()
        .map(|col| {
            let logical_type = match col.logical_type_ref() {
                Some(lt) => format!("{:?}", lt),
                None => "None".to_string(),
            };
            ColumnInfo {
                name: col.name().to_string(),
                physical_type: col.physical_type().to_string(),
                logical_type,
            }
        })
        .collect()
}

pub fn format_ascii_table(columns: &[ColumnInfo]) -> String {
    if columns.is_empty() {
        return "No columns found.".to_string();
    }

    let mut name_width = 11; // "Column Name"
    let mut phys_width = 13; // "Physical Type"
    let mut log_width = 20; // "Logical Type (Arrow)"

    for col in columns {
        name_width = name_width.max(col.name.len());
        phys_width = phys_width.max(col.physical_type.len());
        log_width = log_width.max(col.logical_type.len());
    }

    let separator = format!(
        "+{}+{}+{}+",
        "-".repeat(name_width + 2),
        "-".repeat(phys_width + 2),
        "-".repeat(log_width + 2)
    );

    let mut output = String::new();
    output.push_str(&separator);
    output.push('\n');
    output.push_str(&format!(
        "| {:<name_width$} | {:<phys_width$} | {:<log_width$} |\n",
        "Column Name",
        "Physical Type",
        "Logical Type (Arrow)",
        name_width = name_width,
        phys_width = phys_width,
        log_width = log_width
    ));
    output.push_str(&separator);
    output.push('\n');

    for col in columns {
        output.push_str(&format!(
            "| {:<name_width$} | {:<phys_width$} | {:<log_width$} |\n",
            col.name,
            col.physical_type,
            col.logical_type,
            name_width = name_width,
            phys_width = phys_width,
            log_width = log_width
        ));
    }

    output.push_str(&separator);
    output.push('\n');

    output
}
