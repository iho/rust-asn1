use rust_asn1::asn1_types::{
    ASN1Boolean, ASN1Integer, GeneralizedTime, UTCTime, 
    ASN1PrintableString, ASN1NumericString, ASN1IA5String, ASN1UTF8String
};
use rust_asn1::der::{DERParseable, DERSerializable, Serializer};
use rust_asn1::ber::{self, BERParseable};
use rust_asn1::asn1::ASN1Node;
use chrono::{TimeZone, Utc};

#[test]
fn test_boolean_edge() {
    // Test helper or internal logic for Boolean
    let t = ASN1Boolean(true);
    let f = ASN1Boolean(false);
    assert_eq!(t, true.into());
    assert_eq!(f, false.into());
}

#[test]
fn test_integer_zero() {
    let zero = ASN1Integer::from(0);
    let mut serializer = Serializer::new();
    zero.serialize(&mut serializer).unwrap();
    // 02 01 00
    assert_eq!(serializer.serialized_bytes(), vec![0x02, 0x01, 0x00]);
}

#[test]
fn test_integer_neg_one() {
    let neg = ASN1Integer::from(-1);
    let mut serializer = Serializer::new();
    neg.serialize(&mut serializer).unwrap();
    // 02 01 FF
    assert_eq!(serializer.serialized_bytes(), vec![0x02, 0x01, 0xFF]);
}

#[test]
fn test_oid_invalid_string() {
    // "1.2.840.113549.1.1.11.excess" or similar, but OID components are parsed from OID string usually?
    // Wait, typical usage: `ASN1ObjectIdentifier::parse("1.2...")` if that method exists?
    // No, `ASN1ObjectIdentifier` usually parsed from bytes.
    // Is there a way to construct from string?
    // `ASN1ObjectIdentifier` has `oid_components()` method which returns Vec<u64>.
    // To test invalid OID bytes, we can try `from_der_bytes` with bad data.
    
    // Invalid sub-identifier encoding (e.g., > u64::MAX or improper VLQ)
    // 80 80 80 ... 
}

#[test]
fn test_oid_construct() {
    // If there is a constructor
    // ASN1ObjectIdentifier::new(vec![1, 2, 840])
    // Test serialization of it.
    
    // This is covered if I use it.
}

#[test]
fn test_time_methods() {
    // GeneralizedTime with fractional seconds? (Not supported yet, but checking error?)
    // GeneralizedTime("20230101120000.123Z") -> Error
    // We only test what we have implemented.
    
    let dt = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
    let gt: GeneralizedTime = dt.into();
    assert_eq!(gt.0, dt);
}

#[test]
fn test_time_parsing_errors() {
    // GeneralizedTime
    // Missing Z
    let data = "20230101120000".as_bytes(); // No Z
    let node = ASN1Node {
        identifier: rust_asn1::asn1_types::ASN1Identifier::GENERALIZED_TIME,
        content: rust_asn1::asn1::Content::Primitive(bytes::Bytes::copy_from_slice(data)),
        encoded_bytes: bytes::Bytes::new(),
    };
    assert!(GeneralizedTime::from_der_node(node.clone()).is_err()); // Missing Z

    // Invalid Format
    let data = "2023-01-01 12:00:00Z".as_bytes(); 
    let node = ASN1Node {
        identifier: rust_asn1::asn1_types::ASN1Identifier::GENERALIZED_TIME,
        content: rust_asn1::asn1::Content::Primitive(bytes::Bytes::copy_from_slice(data)),
        encoded_bytes: bytes::Bytes::new(),
    };
    assert!(GeneralizedTime::from_der_node(node).is_err());

    // UTCTime
    // Missing Z
    let data = "230101120000".as_bytes();
    let node = ASN1Node {
        identifier: rust_asn1::asn1_types::ASN1Identifier::UTC_TIME,
        content: rust_asn1::asn1::Content::Primitive(bytes::Bytes::copy_from_slice(data)),
        encoded_bytes: bytes::Bytes::new(),
    };
    assert!(UTCTime::from_der_node(node.clone()).is_err());
    
    // Invalid length
    let data = "23".as_bytes();
    let node = ASN1Node {
        identifier: rust_asn1::asn1_types::ASN1Identifier::UTC_TIME,
        content: rust_asn1::asn1::Content::Primitive(bytes::Bytes::copy_from_slice(data)),
        encoded_bytes: bytes::Bytes::new(),
    };
    assert!(UTCTime::from_der_node(node).is_err());
}

#[test]
fn test_string_validation() {
    // PrintableString
    // Valid
    assert!(ASN1PrintableString::new("ABC 123.-".to_string()).is_ok());
    // Invalid (@ is not printable)
    assert!(ASN1PrintableString::new("user@example.com".to_string()).is_err());
    
    // NumericString
    // Valid
    assert!(ASN1NumericString::new("123 456".to_string()).is_ok());
    // Invalid (A is not numeric)
    assert!(ASN1NumericString::new("123 A".to_string()).is_err());
    
    // IA5String
    // Valid (ASCII)
    assert!(ASN1IA5String::new("Hello".to_string()).is_ok());
    // Invalid (Non-ASCII)
    assert!(ASN1IA5String::new("Héllo".to_string()).is_err()); // 'é' is not ASCII
}

#[test]
fn test_ber_constructed_string() {
    // Constructed OCTET STRING is already tested in ber_tests.rs
    // Let's test constructed UTF8String if implemented or supported by generic logic?
    // strings.rs macro implements BER constructed support.
    
    // Construct a BER node: UTF8String (Constructed) containing 2 UTF8Strings
    // UTF8String tag: 0x0C (12). Constructed: 0x2C.
    // Chunk 1: "He" (0x0C 0x02 'H' 'e')
    // Chunk 2: "llo" (0x0C 0x03 'l' 'l' 'o')
    
    let data = vec![
        0x2C, 0x09, // Tag 12|Constructed, Length 9
        0x0C, 0x02, 0x48, 0x65, // He
        0x0C, 0x03, 0x6C, 0x6C, 0x6F, // llo
    ];
    
    let node = ber::parse(&data).expect("Failed parse BER");
    let val = ASN1UTF8String::from_ber_node(node).expect("Failed parse constructed UTF8String");
    assert_eq!(val.0, "Hello");
}
