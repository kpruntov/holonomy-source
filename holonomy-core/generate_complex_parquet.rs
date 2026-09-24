use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::{WriterProperties, WriterVersion};
use std::fs::File;
use std::sync::Arc;

fn main() {
    let mut fields = vec![Field::new("id", DataType::Int64, false)];
    for i in 1..=6 {
        fields.push(Field::new(&format!("col_{}", i), DataType::String, false));
    }
    for i in 1..=3 {
        fields.push(Field::new(&format!("sens_{}", i), DataType::String, false));
    }
    let schema = Arc::new(Schema::new(fields));

    let ids: Vec<i64> = (0..1000).collect();
    let id_array = Int64Array::from(ids);
    
    let mut arrays: Vec<Arc<dyn arrow::array::Array>> = vec![Arc::new(id_array)];
    for _ in 1..=6 {
        let vals: Vec<String> = (0..1000).map(|i| format!("val_{}", i)).collect();
        arrays.push(Arc::new(StringArray::from(vals)));
    }
    for _ in 1..=3 {
        let vals: Vec<String> = (0..1000).map(|i| format!("secret_{}", i)).collect();
        arrays.push(Arc::new(StringArray::from(vals)));
    }

    let batch = RecordBatch::try_new(schema, arrays).unwrap();
    let file = File::create("complex.parquet").unwrap();
    
    // We would add FileEncryptionProperties here if supported, but let's just write plaintext first to check imports
    let props = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_max_row_group_size(100)
        .build();
    let mut writer = ArrowWriter::try_new(file, batch.schema(), Some(props)).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
}
