use rust_asn1::ber::{self, BERParseable};
use rust_asn1::asn1_types::{ASN1OctetString, ASN1Integer, ASN1BitString};
use rust_asn1::asn1::ASN1Node;

#[test]
fn test_ber_parse_primitive() {
    // Integer 42: 02 01 2A
    let data = vec![0x02, 0x01, 0x2A];
    let node = ber::parse(&data).expect("Failed to parse BER");
    assert!(!node.is_constructed());
    
    let val = ASN1Integer::from_ber_node(node).expect("Failed to parse Integer");
    assert_eq!(val, ASN1Integer::from(42));
}

#[test]
fn test_ber_parse_constructed_octet_string() {
    // Constructed OCTET STRING
    // Tag 0x24 (Universal 4 + Constructed 0x20)
    // Length: 10 (2 * (2 + 3)) => 0x0A
    //   Tag 04 Length 03 "ABC"
    //   Tag 04 Length 03 "DEF"
    let data = vec![
        0x24, 0x0A, 
        0x04, 0x03, 0x41, 0x42, 0x43, // ABC
        0x04, 0x03, 0x44, 0x45, 0x46, // DEF
    ];
    
    let node = ber::parse(&data).expect("Failed to parse BER");
    assert!(node.is_constructed());
    
    let val = ASN1OctetString::from_ber_node(node).expect("Failed to parse Octet String");
    assert_eq!(val.0, "ABCDEF".as_bytes());
}

#[test]
fn test_ber_parse_constructed_bit_string() {
    // Constructed BIT STRING (tag 3, 0x23)
    //   BIT STRING (tag 3), padding 0, "A" (0x41) -> 03 02 00 41
    //   BIT STRING (tag 3), padding 4, "B" (0x42) -> 03 02 04 42
    // Result: A + B(shifted/padded?)
    // Actually, bit string bytes are just concatenated? 
    // And "total_padding = part.padding_bits".
    // If the last part has padding, effectively those bits are unused in the last byte.
    // The previous bytes are just concatenated.
    // So if first part is 0 bits padded, it yields full bytes.
    
    let data = vec![
        0x23, 0x08, // Tag 0x23, Len 8
        0x03, 0x02, 0x00, 0x41, // Padding 0, Byte 0x41
        0x03, 0x02, 0x04, 0x42, // Padding 4, Byte 0x42
    ];
    
    let node = ber::parse(&data).expect("Failed to parse BER");
    let val = ASN1BitString::from_ber_node(node).expect("Failed to parse Bit String");
    
    assert_eq!(val.padding_bits, 4);
    assert_eq!(val.bytes, bytes::Bytes::from(vec![0x41, 0x42]));
}


#[test]
fn test_ber_sequence() {
    // SEQUENCE { Integer(10) }
    // 30 03 02 01 0A
    let data = vec![0x30, 0x03, 0x02, 0x01, 0x0A];
    let node = ber::parse(&data).expect("Failed to parse BER");
    
    let val: i32 = ber::sequence(node, rust_asn1::asn1_types::ASN1Identifier::SEQUENCE, |iter| {
        let n: ASN1Node = iter.next().unwrap();
        let i = ASN1Integer::from_ber_node(n)?;
        if i == ASN1Integer::from(10) {
            Ok(10)
        } else {
             Err(rust_asn1::errors::ASN1Error::new(rust_asn1::errors::ErrorCode::InvalidASN1Object, "Wrong int".into(), "".into(), 0))
        }
    }).expect("Failed to parse sequence");
    
    assert_eq!(val, 10);
}

#[test]
fn test_from_ber_iterator_error() {
   // Empty sequence: 30 00
   let data = vec![0x30, 0x00];
   let node = ber::parse(&data).expect("Failed to parse BER");
   
   let res: Result<(), _> = ber::sequence(node, rust_asn1::asn1_types::ASN1Identifier::SEQUENCE, |iter| {
       // Try to read an Integer from empty iterator
       let _ = ASN1Integer::from_ber_iterator(iter)?;
       Ok(())
   });
   
   assert!(res.is_err());
}
