use rust_asn1::asn1_types::ASN1Boolean;
use bytes::Bytes;
use rust_asn1::ber::BERParseable;

#[test]
fn test_ber_boolean_lax() {
    // 0x01 (Length 1) 0x01 (True in BER, but not 0xFF)
    // tag for boolean is 1
    let data = Bytes::from(vec![
        0x01, 0x01, 0x01
    ]);
    
    // Construct node manually or parse? 
    // ber::parse will return ASN1Node.
    // Then ASN1Boolean::from_ber_node
    
    let node = rust_asn1::ber::parse(&data).unwrap();
    let b = ASN1Boolean::from_ber_node(node).unwrap();
    assert_eq!(b.0, true);
    
    // 0x00 is false
    let data2 = Bytes::from(vec![
        0x01, 0x01, 0x00
    ]);
    let node2 = rust_asn1::ber::parse(&data2).unwrap();
    let b2 = ASN1Boolean::from_ber_node(node2).unwrap();
    assert_eq!(b2.0, false);
    
    // 0xFF is true
    let data3 = Bytes::from(vec![
        0x01, 0x01, 0xFF
    ]);
    let node3 = rust_asn1::ber::parse(&data3).unwrap();
    let b3 = ASN1Boolean::from_ber_node(node3).unwrap();
    assert_eq!(b3.0, true);
}
