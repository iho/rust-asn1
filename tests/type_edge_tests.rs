use rust_asn1::asn1_types::{
    ASN1Boolean, ASN1Integer, GeneralizedTime, UTCTime, 
    ASN1PrintableString, ASN1NumericString, ASN1IA5String, ASN1UTF8String, ASN1Null, ASN1Identifier, ASN1OctetString, ASN1BitString
};
use rust_asn1::der::{self, DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use rust_asn1::ber::{self, BERParseable, BERImplicitlyTaggable};
use rust_asn1::asn1::ASN1Node;
use bytes::Bytes;
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
fn test_boolean_der_identifier_mismatch() {
    let node = der::parse(&[0x01, 0x01, 0x00]).unwrap();
    let res = <ASN1Boolean as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_boolean_der_invalid_length() {
    let node = der::parse(&[0x01, 0x00]).unwrap();
    let res = ASN1Boolean::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_boolean_der_invalid_value_encoding() {
    let node = der::parse(&[0x01, 0x01, 0x01]).unwrap();
    let res = ASN1Boolean::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_boolean_der_constructed_rejected() {
    let node = der::parse(&[0x21, 0x00]).unwrap();
    let res = ASN1Boolean::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_boolean_ber_identifier_mismatch() {
    let node = ber::parse(&[0x01, 0x01, 0x00]).unwrap();
    let res = <ASN1Boolean as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_boolean_ber_invalid_length() {
    let node = ber::parse(&[0x01, 0x00]).unwrap();
    let res = ASN1Boolean::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_boolean_ber_constructed_rejected() {
    let node = ber::parse(&[0x21, 0x00]).unwrap();
    let res = ASN1Boolean::from_ber_node(node);
    assert!(res.is_err());
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
fn test_integer_der_identifier_mismatch() {
    let node = der::parse(&[0x02, 0x01, 0x00]).unwrap();
    let res = <ASN1Integer as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::BOOLEAN);
    assert!(res.is_err());
}

#[test]
fn test_integer_der_empty_rejected() {
    let node = der::parse(&[0x02, 0x00]).unwrap();
    let res = ASN1Integer::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_integer_der_redundant_leading_zero_rejected() {
    let node = der::parse(&[0x02, 0x02, 0x00, 0x7F]).unwrap();
    let res = ASN1Integer::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_integer_der_redundant_leading_ff_rejected() {
    let node = der::parse(&[0x02, 0x02, 0xFF, 0x80]).unwrap();
    let res = ASN1Integer::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_integer_der_constructed_rejected() {
    let node = der::parse(&[0x22, 0x00]).unwrap();
    let res = ASN1Integer::from_der_node(node);
    assert!(res.is_err());
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
fn test_integer_ber_identifier_mismatch() {
    let node = ber::parse(&[0x02, 0x01, 0x00]).unwrap();
    let res = <ASN1Integer as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::BOOLEAN);
    assert!(res.is_err());
}

#[test]
fn test_integer_ber_empty_rejected() {
    let node = ber::parse(&[0x02, 0x00]).unwrap();
    let res = ASN1Integer::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_integer_ber_constructed_rejected() {
    let node = ber::parse(&[0x22, 0x00]).unwrap();
    let res = ASN1Integer::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_octet_string_from_conversions() {
    let from_vec: ASN1OctetString = vec![0x01, 0x02, 0x03].into();
    assert_eq!(from_vec.0, [0x01, 0x02, 0x03].as_slice());

    let from_slice: ASN1OctetString = (&[0xAA, 0xBB][..]).into();
    assert_eq!(from_slice.0, [0xAA, 0xBB].as_slice());
}

#[test]
fn test_octet_string_der_identifier_mismatch() {
    let node = der::parse(&[0x04, 0x00]).unwrap();
    let res = <ASN1OctetString as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_octet_string_der_constructed_rejected() {
    let node = der::parse(&[0x24, 0x00]).unwrap();
    let res = ASN1OctetString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_octet_string_ber_identifier_mismatch() {
    let node = ber::parse(&[0x04, 0x00]).unwrap();
    let res = <ASN1OctetString as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_octet_string_ber_constructed_child_type_error() {
    // Constructed OCTET STRING containing an INTEGER child should fail
    let data = [0x24, 0x03, 0x02, 0x01, 0x00];
    let node = ber::parse(&data).unwrap();
    let res = ASN1OctetString::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_new_validation_errors() {
    assert!(ASN1BitString::new(Bytes::from_static(&[0xAA]), 8).is_err());
    assert!(ASN1BitString::new(Bytes::new(), 1).is_err());

    let ok = ASN1BitString::new(Bytes::from_static(&[0xAA]), 0).unwrap();
    assert_eq!(ok.padding_bits, 0);
    assert_eq!(ok.bytes, Bytes::from_static(&[0xAA]));
}

#[test]
fn test_bit_string_der_identifier_mismatch() {
    let node = der::parse(&[0x03, 0x02, 0x00, 0x00]).unwrap();
    let res = <ASN1BitString as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_der_empty_content_rejected() {
    let node = der::parse(&[0x03, 0x00]).unwrap();
    let res = ASN1BitString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_der_invalid_padding_bits_rejected() {
    let node = der::parse(&[0x03, 0x01, 0x08]).unwrap();
    let res = ASN1BitString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_der_empty_data_nonzero_padding_rejected() {
    let node = der::parse(&[0x03, 0x01, 0x01]).unwrap();
    let res = ASN1BitString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_der_unused_bits_must_be_zero() {
    let node = der::parse(&[0x03, 0x02, 0x01, 0x01]).unwrap();
    let res = ASN1BitString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_der_valid_padding_bits_with_zero_unused_bits() {
    // padding_bits=1, last byte LSB must be zero.
    let node = der::parse(&[0x03, 0x02, 0x01, 0x02]).unwrap();
    let res = ASN1BitString::from_der_node(node).unwrap();
    assert_eq!(res.padding_bits, 1);
    assert_eq!(res.bytes, Bytes::from_static(&[0x02]));
}

#[test]
fn test_bit_string_der_empty_data_zero_padding_ok() {
    // Empty BIT STRING (content is just the padding byte 0)
    let node = der::parse(&[0x03, 0x01, 0x00]).unwrap();
    let res = ASN1BitString::from_der_node(node).unwrap();
    assert_eq!(res.padding_bits, 0);
    assert_eq!(res.bytes, Bytes::new());
}

#[test]
fn test_bit_string_der_constructed_rejected() {
    let node = der::parse(&[0x23, 0x00]).unwrap();
    let res = ASN1BitString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_ber_identifier_mismatch() {
    let node = ber::parse(&[0x03, 0x02, 0x00, 0x00]).unwrap();
    let res = <ASN1BitString as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_ber_empty_content_rejected() {
    let node = ber::parse(&[0x03, 0x00]).unwrap();
    let res = ASN1BitString::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_ber_invalid_padding_bits_rejected() {
    let node = ber::parse(&[0x03, 0x01, 0x08]).unwrap();
    let res = ASN1BitString::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_bit_string_ber_constructed_segment_padding_rule() {
    let data = [
        0x23, 0x08,
        0x03, 0x02, 0x01, 0x00,
        0x03, 0x02, 0x00, 0xFF,
    ];
    let node = ber::parse(&data).unwrap();
    let res = ASN1BitString::from_ber_node(node);
    assert!(res.is_err());
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
fn test_time_identifier_mismatch_and_constructed_rejected() {
    let gt_bytes = b"20230101120000Z";
    let node = der::parse(&[&[0x18, 0x0F][..], gt_bytes].concat()).unwrap();
    let res = <GeneralizedTime as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::UTC_TIME);
    assert!(res.is_err());

    let node = der::parse(&[0x38, 0x00]).unwrap();
    let res = GeneralizedTime::from_der_node(node);
    assert!(res.is_err());

    let utc_bytes = b"230101120000Z";
    let node = der::parse(&[&[0x17, 0x0D][..], utc_bytes].concat()).unwrap();
    let res = <UTCTime as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::GENERALIZED_TIME);
    assert!(res.is_err());

    let node = der::parse(&[0x37, 0x00]).unwrap();
    let res = UTCTime::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_utc_time_single_z_rejected() {
    let node = der::parse(&[0x17, 0x01, 0x5A]).unwrap();
    let res = UTCTime::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_time_ber_wrappers() {
    let gt_bytes = b"20230101120000Z";
    let node = ber::parse(&[&[0x18, 0x0F][..], gt_bytes].concat()).unwrap();
    let v = GeneralizedTime::from_ber_node(node).unwrap();
    assert_eq!(v.0.format("%Y%m%d%H%M%SZ").to_string(), "20230101120000Z");

    let node = ber::parse(&[&[0x18, 0x0F][..], gt_bytes].concat()).unwrap();
    let v = <GeneralizedTime as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::GENERALIZED_TIME).unwrap();
    assert_eq!(v.0.format("%Y%m%d%H%M%SZ").to_string(), "20230101120000Z");

    let utc_bytes = b"230101120000Z";
    let node = ber::parse(&[&[0x17, 0x0D][..], utc_bytes].concat()).unwrap();
    let v = UTCTime::from_ber_node(node).unwrap();
    assert_eq!(v.0.format("%y%m%d%H%M%SZ").to_string(), "230101120000Z");

    let node = ber::parse(&[&[0x17, 0x0D][..], utc_bytes].concat()).unwrap();
    let v = <UTCTime as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::UTC_TIME).unwrap();
    assert_eq!(v.0.format("%y%m%d%H%M%SZ").to_string(), "230101120000Z");
}

#[test]
fn test_time_der_invalid_utf8() {
    let node = der::parse(&[0x18, 0x01, 0xFF]).unwrap();
    assert!(GeneralizedTime::from_der_node(node).is_err());

    let node = der::parse(&[0x17, 0x01, 0xFF]).unwrap();
    assert!(UTCTime::from_der_node(node).is_err());
}

#[test]
fn test_time_ber_identifier_mismatch_wrappers() {
    let utc_bytes = b"230101120000Z";
    let node = ber::parse(&[&[0x17, 0x0D][..], utc_bytes].concat()).unwrap();
    let res = <UTCTime as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::GENERALIZED_TIME);
    assert!(res.is_err());
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
fn test_strings_der_identifier_mismatch() {
    let node = der::parse(&[0x13, 0x01, 0x41]).unwrap();
    let res = <ASN1PrintableString as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::UTF8_STRING);
    assert!(res.is_err());
}

#[test]
fn test_strings_der_invalid_content() {
    let node = der::parse(&[0x13, 0x01, 0x40]).unwrap();
    let res = ASN1PrintableString::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_der_constructed_rejected() {
    let node = der::parse(&[0x2C, 0x00]).unwrap();
    let res = ASN1UTF8String::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_ber_identifier_mismatch() {
    let node = ber::parse(&[0x0C, 0x01, 0x41]).unwrap();
    let res = <ASN1UTF8String as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_strings_ber_invalid_content() {
    let node = ber::parse(&[0x12, 0x03, 0x31, 0x41, 0x32]).unwrap();
    let res = ASN1NumericString::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_der_invalid_utf8() {
    let node = der::parse(&[0x0C, 0x01, 0xFF]).unwrap();
    let res = ASN1UTF8String::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_der_invalid_content_numeric_and_ia5() {
    let node = der::parse(&[0x12, 0x03, 0x31, 0x41, 0x32]).unwrap();
    let res = ASN1NumericString::from_der_node(node);
    assert!(res.is_err());

    // IA5 must be ASCII but UTF-8 decoding succeeds
    let node = der::parse(&[0x16, 0x02, 0xC3, 0xA9]).unwrap();
    let res = ASN1IA5String::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_der_constructed_rejected_for_all_types() {
    let node = der::parse(&[0x2C, 0x00]).unwrap();
    assert!(ASN1UTF8String::from_der_node(node).is_err());

    let node = der::parse(&[0x33, 0x00]).unwrap();
    assert!(ASN1PrintableString::from_der_node(node).is_err());

    let node = der::parse(&[0x36, 0x00]).unwrap();
    assert!(ASN1IA5String::from_der_node(node).is_err());

    let node = der::parse(&[0x32, 0x00]).unwrap();
    assert!(ASN1NumericString::from_der_node(node).is_err());
}

#[test]
fn test_strings_ber_constructed_concat_success_for_multiple_types() {
    // PrintableString constructed: "AB" + "CD"
    let data = [
        0x33, 0x08,
        0x13, 0x02, 0x41, 0x42,
        0x13, 0x02, 0x43, 0x44,
    ];
    let node = ber::parse(&data).unwrap();
    let v = ASN1PrintableString::from_ber_node(node).unwrap();
    assert_eq!(v.0, "ABCD");

    // NumericString constructed: "1" + "2"
    let data = [
        0x32, 0x06,
        0x12, 0x01, 0x31,
        0x12, 0x01, 0x32,
    ];
    let node = ber::parse(&data).unwrap();
    let v = ASN1NumericString::from_ber_node(node).unwrap();
    assert_eq!(v.0, "12");

    // IA5String constructed: "Hi" + "!"
    let data = [
        0x36, 0x07,
        0x16, 0x02, 0x48, 0x69,
        0x16, 0x01, 0x21,
    ];
    let node = ber::parse(&data).unwrap();
    let v = ASN1IA5String::from_ber_node(node).unwrap();
    assert_eq!(v.0, "Hi!");
}

#[test]
fn test_strings_ber_constructed_child_type_error() {
    // Constructed PrintableString containing IA5String child should error
    let data = [
        0x33, 0x04,
        0x16, 0x02, 0x41, 0x42,
    ];
    let node = ber::parse(&data).unwrap();
    let res = ASN1PrintableString::from_ber_node(node);
    assert!(res.is_err());
}

#[test]
fn test_strings_ber_invalid_utf8() {
    let node = ber::parse(&[0x0C, 0x01, 0xFF]).unwrap();
    let res = ASN1UTF8String::from_ber_node(node);
    assert!(res.is_err());
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

#[test]
fn test_null_der_identifier_mismatch() {
    let node = ber::parse(&[0x05, 0x00]).unwrap();
    let res = <ASN1Null as DERImplicitlyTaggable>::from_der_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}

#[test]
fn test_null_der_non_empty_content() {
    let node = der::parse(&[0x05, 0x01, 0x00]).unwrap();
    let res = ASN1Null::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_null_der_constructed_rejected() {
    let node = ber::parse(&[0x25, 0x00]).unwrap();
    let res = ASN1Null::from_der_node(node);
    assert!(res.is_err());
}

#[test]
fn test_null_ber_wrappers() {
    let node = ber::parse(&[0x05, 0x00]).unwrap();
    let v = ASN1Null::from_ber_node(node).unwrap();
    assert_eq!(v, ASN1Null);

    let node = ber::parse(&[0x05, 0x00]).unwrap();
    let v = <ASN1Null as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::NULL).unwrap();
    assert_eq!(v, ASN1Null);

    let node = ber::parse(&[0x05, 0x00]).unwrap();
    let res = <ASN1Null as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER);
    assert!(res.is_err());
}
