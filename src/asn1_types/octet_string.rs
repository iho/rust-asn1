use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ASN1OctetString(pub Bytes);

impl From<Vec<u8>> for ASN1OctetString {
    fn from(v: Vec<u8>) -> Self {
        ASN1OctetString(Bytes::from(v))
    }
}

impl From<&[u8]> for ASN1OctetString {
    fn from(v: &[u8]) -> Self {
        ASN1OctetString(Bytes::copy_from_slice(v))
    }
}

impl DERParseable for ASN1OctetString {
     fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1OctetString::default_identifier())
    }
}

impl DERSerializable for ASN1OctetString {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
        serializer.append_primitive_node(Self::default_identifier(), |buf| {
            buf.extend_from_slice(&self.0);
            Ok(())
        })
    }
}

impl DERImplicitlyTaggable for ASN1OctetString {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::OCTET_STRING
    }
     fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                Ok(ASN1OctetString(bytes))
            },
            // DER Octet String must be primitive
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "DER OCTET STRING must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

// BER allows constructed OCTET STRING.
impl BERParseable for ASN1OctetString {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
         Self::from_ber_node_with_identifier(node, ASN1OctetString::default_identifier())
    }
}
impl BERSerializable for ASN1OctetString {}
impl BERImplicitlyTaggable for ASN1OctetString {
     fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                Ok(ASN1OctetString(bytes))
            },
            crate::asn1::Content::Constructed(collection) => {
                // Constructed BER OCTET STRING is concatenation of children
                let mut result = Vec::new();
                for child in collection {
                    let part = ASN1OctetString::from_ber_node(child)?;
                    result.extend_from_slice(&part.0);
                }
                Ok(ASN1OctetString(Bytes::from(result)))
            }
        }
    }
}
