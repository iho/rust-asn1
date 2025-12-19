use rust_asn1::asn1_types::{ASN1Boolean, ASN1Integer, ASN1OctetString, ASN1ObjectIdentifier, GeneralizedTime, UTCTime, ASN1Null, ASN1BitString, ASN1UTF8String, ASN1PrintableString, ASN1IA5String, ASN1NumericString};
use rust_asn1::der::{DERParseable, Serializer};
use num_bigint::BigInt;
use chrono::{Utc, TimeZone};
use std::fs;
use std::path::Path;
use bytes::Bytes;

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

#[test]
fn test_null() {
    let bytes = read_golden("null.der");
    let val = ASN1Null::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val, ASN1Null);
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_bit_string() {
    let bytes = read_golden("bit_string.der");
    let val = ASN1BitString::from_der_bytes(&bytes).expect("Parse failed");
    // OpenSSL encoded the string "0A3B5F291CD" as ASCII bytes, so padding is 0.
    assert_eq!(val.padding_bits, 0); 
    assert_eq!(val.bytes.len(), 11);
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_utf8_string() {
    let bytes = read_golden("utf8_string.der");
    let val = ASN1UTF8String::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "Hello UTF8");
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_printable_string() {
    let bytes = read_golden("printable_string.der");
    let val = ASN1PrintableString::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "Hello Printable");
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_ia5_string() {
    let bytes = read_golden("ia5_string.der");
    let val = ASN1IA5String::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "Hello IA5");
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}

#[test]
fn test_numeric_string() {
    let bytes = read_golden("numeric_string.der");
    let val = ASN1NumericString::from_der_bytes(&bytes).expect("Parse failed");
    assert_eq!(val.0, "1234567890");
    
    let mut serializer = Serializer::new();
    serializer.serialize(&val).expect("Serialize failed");
    assert_eq!(serializer.serialized_bytes(), bytes);
}
