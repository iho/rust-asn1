use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ASN1Null;

impl DERParseable for ASN1Null {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1Null::default_identifier())
    }
}

impl DERSerializable for ASN1Null {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
         serializer.append_primitive_node(Self::default_identifier(), |_| Ok(()))
    }
}

impl DERImplicitlyTaggable for ASN1Null {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::NULL
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if !bytes.is_empty() {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "NULL must have 0 length".to_string(), file!().to_string(), line!()));
                }
                Ok(ASN1Null)
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "NULL must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

impl BERParseable for ASN1Null {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1Null::default_identifier())
    }
}
impl BERSerializable for ASN1Null {}
impl BERImplicitlyTaggable for ASN1Null {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, identifier)
    }
}
