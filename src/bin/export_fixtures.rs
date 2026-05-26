use spartan_whir_export::fixture_export::{export_current_fixtures, prepare_output_dir};

fn main() -> anyhow::Result<()> {
    let out_dir = prepare_output_dir("export_fixtures")?;
    export_current_fixtures(&out_dir)
}
