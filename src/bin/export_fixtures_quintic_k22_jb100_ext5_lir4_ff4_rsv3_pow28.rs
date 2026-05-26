use spartan_whir_export::fixture_export::{
    export_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28_fixtures, prepare_output_dir,
};

fn main() -> anyhow::Result<()> {
    let out_dir = prepare_output_dir("export_fixtures_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28")?;
    export_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28_fixtures(&out_dir)
}
