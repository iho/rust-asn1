use rust_asn1::asn1_types::{ASN1Boolean, ASN1Integer, ASN1OctetString, ASN1ObjectIdentifier, GeneralizedTime, UTCTime};
use rust_asn1::der::{DERParseable, Serializer};
use num_bigint::BigInt;
use chrono::{Utc, TimeZone};
use std::fs;
use std::path::Path;

fn read_golden(name: &str) -> Vec<u8> {
    let path = Path::new("tests/golden").join(name);
    fs::read(&path).expect(&format!("Failed to read golden file: {}", path.display()))
}

#[test]
fn test_boolean_true() {
    let bytes = read_golden("true.der");
    let val = ASN1Boolean::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val, ASN1Boolean(true));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_boolean_false() {
    let bytes = read_golden("false.der");
    let val = ASN1Boolean::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val, ASN1Boolean(false));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_integer_42() {
    let bytes = read_golden("int_42.der");
    let val = ASN1Integer::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val, ASN1Integer::from(42));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_integer_neg1() {
    let bytes = read_golden("int_neg1.der");
    let val = ASN1Integer::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val, ASN1Integer::from(-1));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_integer_large() {
    let bytes = read_golden("int_large.der");
    let val = ASN1Integer::from_der_bytes(&bytes).expect("Parse failed");
    
    // 0x0102030405060708
    let expected = BigInt::parse_bytes(b"0102030405060708", 16).unwrap();
    assert_eq!(val, ASN1Integer::from(expected));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_octet_string() {
    let bytes = read_golden("octet_string.der");
    let val = ASN1OctetString::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "Hello World".as_bytes());
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_octet_string_empty() {
    let bytes = read_golden("octet_string_empty.der");
    let val = ASN1OctetString::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "".as_bytes());
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_oid() {
    let bytes = read_golden("oid.der");
    let val = ASN1ObjectIdentifier::from_der_bytes(&bytes).expect("Parse failed");
    let components = val.oid_components().expect("Failed to get components");
    assert_eq!(components, vec![1, 2, 840, 113549, 1, 1, 11]);
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_generalized_time() {
    let bytes = read_golden("generalized_time.der");
    let val = GeneralizedTime::from_der_bytes(&bytes).expect("Parse failed");
    
    let expected = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
    assert_eq!(val, GeneralizedTime(expected));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_utc_time() {
    let bytes = read_golden("utc_time.der");
    let val = UTCTime::from_der_bytes(&bytes).expect("Parse failed");
    
    let expected = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
    assert_eq!(val, UTCTime(expected));
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}
