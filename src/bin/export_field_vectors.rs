use std::{fs, path::PathBuf};

use spartan_whir_export::vectors::generate_field_vectors;

fn main() -> anyhow::Result<()> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("usage: export-field-vectors <output-dir>"))?,
    );
    fs::create_dir_all(&out_dir)?;
    let encoded = serde_json::to_vec_pretty(&generate_field_vectors())?;
    fs::write(out_dir.join("field_vectors.json"), encoded)?;
    Ok(())
}
