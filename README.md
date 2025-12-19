# rust-asn1

`rust-asn1` is a pure-Rust playground for parsing, validating, and serializing ASN.1 data under both DER and BER encoding rules.  The project mirrors the APIs provided by Swift’s `swift-asn1` package while embracing Rust idioms—`Result`-based error handling, ownership, and strict mutation testing—so it’s easy to cross-reference behavior between the two ecosystems.

## Features

- **Low-level primitives** – `ASN1Integer`, `ASN1BitString`, `ASN1ObjectIdentifier`, strings, times, and more.
- **DER/BER parsing** – `der::parse`, `der::sequence_of`, and corresponding BER helpers convert raw byte slices into high-level nodes.
- **Serializer** – Construct DER output by appending primitive nodes or serializing entire structures.
- **Robust validation** – Length checks, padding rules, OID encoding rules, recursion limits, and more.
- **Mutation-tested** – The repository relies on `cargo-mutants` to ensure unit tests detect logic changes.

## Repository layout

| Path | Description |
| --- | --- |
| `src/asn1.rs` | Core parser, AST (`ParserNode`, `ASN1NodeCollection`), and parsing utilities. |
| `src/der.rs` / `src/ber.rs` | DER/BER-specific helpers (parsing, serializers, helper traits). |
| `src/asn1_types/` | Implementations of concrete ASN.1 types (integer, bit string, OID, time, etc.). |
| `tests/` | Edge-case and integration tests mirroring Swift test suites. |
| `Makefile` | Convenience targets (`make mutant`, `make test`, etc.). |

## Getting started

```bash
# 1. Fetch dependencies + run the full test suite
cargo test

# 2. Optional: run mutation tests (beware this is slow)
make mutant
```

### Toolchain prerequisites

- Rust 1.72+ (the repo targets edition 2024)
- `cargo-mutants` (`cargo install --locked cargo-mutants`)

## Usage examples

### Parsing DER bytes

```rust
use rust_asn1::der;
use rust_asn1::asn1_types::ASN1Integer;

let node = der::parse(&[0x02, 0x01, 0x2A])?;
let value = ASN1Integer::from_der_node(node)?;
assert_eq!(value.value, 42.into());
```

### Serializing primitives

```rust
use rust_asn1::der::{Serializer, DERSerializable};
use rust_asn1::asn1_types::ASN1Integer;

let int = ASN1Integer::from(9001);
let mut serializer = Serializer::new();
int.serialize(&mut serializer)?;
let bytes = serializer.serialized_bytes();
```

### Working with BER helper methods

```rust
use rust_asn1::asn1_types::{ASN1OctetString, DERImplicitlyTaggable};
use rust_asn1::der;

let node = der::parse(&[0x04, 0x03, 0xDE, 0xAD, 0xBE])?;
let octets = ASN1OctetString::from_der_node(node)?;
assert_eq!(octets.0.as_ref(), &[0xDE, 0xAD, 0xBE]);
```

## Testing & mutation testing

| Command | Description |
| --- | --- |
| `cargo test` | Runs unit, integration, and doc tests. |
| `make mutant` | Runs `cargo mutants --timeout 20 --jobs 10` (edit the Makefile to change defaults). |

> Tip: mutation runs are heavy; consider lowering `--jobs` to 4–6 on laptops.

## Contributing

1. Fork and clone the repo.
2. Run `cargo fmt` + `cargo clippy` (if installed) before committing.
3. Ensure `cargo test` passes.
4. Run `make mutant` (or targeted mutants) before opening a PR if practical.

Bug reports and PRs are welcome!  The goal is to keep this codebase aligned with Swift’s ASN.1 behavior while showcasing idiomatic Rust.  If you spot divergences or missing coverage, file an issue or submit a patch.
