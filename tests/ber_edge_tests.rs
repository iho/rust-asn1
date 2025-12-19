use rust_asn1::asn1_types::ASN1Boolean;
use bytes::Bytes;
use rust_asn1::ber::{self, BERImplicitlyTaggable, BERParseable};
use rust_asn1::asn1_types::ASN1Identifier;
use rust_asn1::der::{DERImplicitlyTaggable, DERParseable, DERSerializable, Serializer};
use rust_asn1::errors::{ASN1Error, ErrorCode};
use rust_asn1::asn1::ASN1Node;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dummy(u8);

impl DERParseable for Dummy {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        match node.content {
            rust_asn1::asn1::Content::Primitive(bytes) => {
                if bytes.is_empty() {
                    return Err(ASN1Error::new(
                        ErrorCode::InvalidASN1Object,
                        "".to_string(),
                        file!().to_string(),
                        line!(),
                    ));
                }
                Ok(Dummy(bytes[0]))
            }
            _ => Err(ASN1Error::new(
                ErrorCode::UnexpectedFieldType,
                "".to_string(),
                file!().to_string(),
                line!(),
            )),
        }
    }
}

impl DERSerializable for Dummy {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
        serializer.append_primitive_node(Self::default_identifier(), |buf| {
            buf.push(self.0);
            Ok(())
        })
    }
}

impl DERImplicitlyTaggable for Dummy {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::INTEGER
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
            return Err(ASN1Error::new(
                ErrorCode::UnexpectedFieldType,
                "".to_string(),
                file!().to_string(),
                line!(),
            ));
        }
        Self::from_der_node(node)
    }
}

impl BERParseable for Dummy {}
impl rust_asn1::ber::BERSerializable for Dummy {}
impl BERImplicitlyTaggable for Dummy {}

#[test]
fn test_ber_default_from_ber_node_and_with_identifier() {
    let node = ber::parse(&[0x02, 0x01, 0x2A]).unwrap();
    let v = Dummy::from_ber_node(node).unwrap();
    assert_eq!(v, Dummy(0x2A));

    let node = ber::parse(&[0x02, 0x01, 0x2A]).unwrap();
    let v = <Dummy as BERImplicitlyTaggable>::from_ber_node_with_identifier(node, ASN1Identifier::INTEGER).unwrap();
    assert_eq!(v, Dummy(0x2A));
}

#[test]
fn test_ber_default_from_ber_iterator() {
    let data = [0x30, 0x03, 0x02, 0x01, 0x2A];
    let node = ber::parse(&data).unwrap();
    let v: Dummy = ber::sequence(node, ASN1Identifier::SEQUENCE, |iter| Dummy::from_ber_iterator(iter)).unwrap();
    assert_eq!(v, Dummy(0x2A));
}
