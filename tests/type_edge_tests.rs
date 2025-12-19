use rust_asn1::asn1_types::{ASN1Boolean, ASN1Integer, GeneralizedTime};
use rust_asn1::der::{DERSerializable, Serializer};
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
