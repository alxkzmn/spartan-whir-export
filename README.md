# spartan-whir-export

Rust crate that generates ABI-encoded test fixtures and JSON test vectors for the [Solidity Spartan-WHIR verifier](https://github.com/alxkzmn/sol-spartan-whir).
WIP workspace with all modules side-by-side for convenience: [spartan-whir-dev](https://github.com/alxkzmn/spartan-whir-dev).

## What it produces

| File                                                   | Format | Purpose                                                                            |
| ------------------------------------------------------ | ------ | ---------------------------------------------------------------------------------- |
| `quartic_whir_lir6_ff5_rsv1_success_proof.abi`         | ABI    | Valid WHIR proof for the current quartic schedule                                  |
| `quartic_whir_lir6_ff5_rsv1_success_statement.abi`     | ABI    | Statement matching the current quartic proof                                       |
| `quartic_whir_lir6_ff5_rsv1_success.blob`              | Blob   | Native blob fixture for the current quartic schedule                               |
| `quartic_whir_lir11_ff5_rsv3_success_proof.abi`        | ABI    | Valid WHIR proof for the alternate quartic schedule                                |
| `quartic_whir_lir11_ff5_rsv3_success_statement.abi`    | ABI    | Statement matching the alternate quartic proof                                     |
| `quartic_whir_lir11_ff5_rsv3_success.blob`             | Blob   | Native blob fixture for the alternate quartic schedule                             |
| `spartan_placeholder_instance.abi`                     | ABI    | Empty Spartan instance for schema testing                                          |
| `spartan_placeholder_proof_quartic_lir6_ff5_rsv1.abi`  | ABI    | Placeholder Spartan proof wrapping the current quartic PCS proof                   |
| `transcript_trace_quartic_lir6_ff5_rsv1.json`          | JSON   | Full prover/verifier Fiat-Shamir transcript trace for the current quartic schedule |
| `spartan_transcript_context_quartic_lir6_ff5_rsv1.abi` | ABI    | Spartan transcript context fixture for the current quartic schedule                |
| `field_vectors.json`                                   | JSON   | Base/quartic/octic field arithmetic vectors                                        |
| `merkle_vectors.json`                                  | JSON   | Leaf hashes, node compressions, multiproof vectors                                 |
| `metadata.json`                                        | JSON   | Schema version, modulus, notes                                                     |

Schedule-specific transcript traces, Spartan transcript contexts, and placeholder Spartan proofs follow the same suffixing rule as the WHIR proof families.

## Usage

```sh
cargo run --release --bin export-fixtures -p spartan-whir-export -- <output-dir>
```

Typical invocation to regenerate the current schedule fixtures plus the shared vectors:

```sh
cargo run --release --bin export-fixtures -p spartan-whir-export -- sol-spartan-whir/testdata
```

Alternate schedule exporter for the `lir=11` family:

```sh
cargo run --release --bin export-fixtures-lir11-ff5-rsv3 -p spartan-whir-export -- sol-spartan-whir/testdata
```

The default `export-fixtures` binary is the `lir6_ff5_rsv1` exporter and keeps writing the shared vectors and metadata. The `export-fixtures-lir11-ff5-rsv3` binary writes only the `lir11_ff5_rsv3` schedule-specific artifacts, so it does not overwrite the current schedule family.

## Crate layout

| Module                                  | Contents                                                      |
| --------------------------------------- | ------------------------------------------------------------- |
| `lib.rs`                                | ABI struct definitions (`sol!` macro) and constants           |
| `fixture_export.rs`                     | Shared schedule-specific export helpers used by the binaries  |
| `quartic_fixture.rs`                    | Builds a complete quartic WHIR prove+verify round             |
| `transcript.rs`                         | `TraceChallenger` — logging wrapper around `KeccakChallenger` |
| `abi_export.rs`                         | Converts Rust proof/statement types to ABI structs            |
| `vectors.rs`                            | Generates field arithmetic and Merkle test vectors            |
| `utils.rs`                              | Shared helpers (hex encoding, extension packing, file I/O)    |
| `bin/export_fixtures.rs`                | Current `lir6_ff5_rsv1` exporter plus shared vectors          |
| `bin/export_fixtures_lir11_ff5_rsv3.rs` | Alternate `lir11_ff5_rsv3` schedule exporter                  |
