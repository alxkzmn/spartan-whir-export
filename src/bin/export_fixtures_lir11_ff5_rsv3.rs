use spartan_whir_export::fixture_export::{export_lir11_fixtures, prepare_output_dir};

fn main() -> anyhow::Result<()> {
    let out_dir = prepare_output_dir("export_fixtures_lir11_ff5_rsv3")?;
    export_lir11_fixtures(&out_dir)
}
