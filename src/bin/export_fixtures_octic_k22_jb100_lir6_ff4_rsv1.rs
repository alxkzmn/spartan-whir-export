use spartan_whir_export::fixture_export::{export_octic_k22_jb100_fixtures, prepare_output_dir};

fn main() -> anyhow::Result<()> {
    let out_dir = prepare_output_dir("export_fixtures_octic_k22_jb100_lir6_ff4_rsv1")?;
    export_octic_k22_jb100_fixtures(&out_dir)
}
