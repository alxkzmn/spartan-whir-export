# spartan-whir-export

Rust crate that generates ABI-encoded test fixtures and JSON test vectors for the [Solidity Spartan-WHIR verifier](https://github.com/alxkzmn/sol-spartan-whir).
WIP workspace with all modules side-by-side for convenience: [spartan-whir-dev](https://github.com/alxkzmn/spartan-whir-dev).

## What it produces

| File                                            | Format | Purpose                                            |
| ----------------------------------------------- | ------ | -------------------------------------------------- |
| `quartic_whir_success_proof.abi`                | ABI    | Valid WHIR proof (quartic extension)               |
| `quartic_whir_success_statement.abi`            | ABI    | Statement matching the success proof               |
| `quartic_whir_success_config.abi`               | ABI    | Expanded WHIR config for the success proof         |
| `quartic_whir_failure_bad_commitment_proof.abi` | ABI    | Tampered proof (mutated initial commitment)        |
| `spartan_placeholder_instance.abi`              | ABI    | Empty Spartan instance for schema testing          |
| `spartan_placeholder_proof.abi`                 | ABI    | Spartan proof wrapping the real PCS proof          |
| `field_vectors.json`                            | JSON   | Base/quartic/octic field arithmetic vectors        |
| `merkle_vectors.json`                           | JSON   | Leaf hashes, node compressions, multiproof vectors |
| `transcript_trace_quartic.json`                 | JSON   | Full prover/verifier Fiat-Shamir transcript trace  |
| `metadata.json`                                 | JSON   | Schema version, modulus, notes                     |

## Usage

```sh
cargo run --bin export-fixtures -p spartan-whir-export -- <output-dir>
```

Typical invocation to regenerate the Foundry test fixtures:

```sh
cargo run --bin export-fixtures -p spartan-whir-export -- sol-spartan-whir/testdata
```

## Crate layout

| Module                   | Contents                                                      |
| ------------------------ | ------------------------------------------------------------- |
| `lib.rs`                 | ABI struct definitions (`sol!` macro) and constants           |
| `quartic_fixture.rs`     | Builds a complete quartic WHIR prove+verify round             |
| `transcript.rs`          | `TraceChallenger` — logging wrapper around `KeccakChallenger` |
| `abi_export.rs`          | Converts Rust proof/config/statement types to ABI structs     |
| `vectors.rs`             | Generates field arithmetic and Merkle test vectors            |
| `utils.rs`               | Shared helpers (hex encoding, extension packing, file I/O)    |
| `bin/export_fixtures.rs` | CLI entry point that wires everything together                |
