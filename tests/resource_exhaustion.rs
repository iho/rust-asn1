use rust_asn1::ber;
use rust_asn1::errors::ErrorCode;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

#[test]
fn test_node_limit_exceeded() {
    // Generate a flat sequence with 100,001 items.
    // 100,001 items + 1 root SEQUENCE = 100,002 nodes.
    // Limit is 100,000.

    let count = 100_001;
    let mut data = Vec::with_capacity(count * 2 + 10);

    // SEQUENCE (indefinite length)
    data.push(0x30);
    data.push(0x80);

    // Items: NULL (0x05 0x00)
    for _ in 0..count {
        data.push(0x05);
        data.push(0x00);
    }

    // End of Content (0x00 0x00)
    data.push(0x00);
    data.push(0x00);

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resource_exhaustion.ber");

    let mut file = File::create(&path).expect("Failed to create file");
    file.write_all(&data).expect("Failed to write data");

    // Read back
    let mut file = File::open(&path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    let result = ber::parse(&buffer);

    assert!(result.is_err(), "Parser should reject excessive node count");
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidASN1Object);
    assert!(format!("{}", err).contains("Excessive number of ASN.1 nodes"));
}
