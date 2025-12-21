use rust_asn1::ber;
use rust_asn1::errors::ErrorCode;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

#[test]
fn test_recursion_limit() {
    let depth = 60;
    let mut data = Vec::new();
    // Open sequences: 0x30 0x80 (Indefinite length)
    for _ in 0..depth {
        data.push(0x30);
        data.push(0x80);
    }
    // Close sequences: 0x00 0x00
    for _ in 0..depth {
        data.push(0x00);
        data.push(0x00);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("excessive_depth.ber");

    let mut file = File::create(&path).expect("Failed to create file");
    file.write_all(&data).expect("Failed to write data");

    let mut file = File::open(&path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    let result = ber::parse(&buffer);

    assert!(result.is_err(), "Parser should reject deep nesting");
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidASN1Object);
    assert!(format!("{}", err).contains("Excessive stack depth"));
}
