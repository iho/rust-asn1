use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ASN1Boolean(pub bool);

impl From<bool> for ASN1Boolean {
    fn from(b: bool) -> Self {
        ASN1Boolean(b)
    }
}

impl From<ASN1Boolean> for bool {
    fn from(val: ASN1Boolean) -> Self {
        val.0
    }
}

impl DERParseable for ASN1Boolean {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1Boolean::default_identifier())
    }
}

impl DERSerializable for ASN1Boolean {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
        serializer.append_primitive_node(Self::default_identifier(), |buf| {
            if self.0 {
                buf.push(0xFF);
            } else {
                buf.push(0x00);
            }
            Ok(())
        })
    }
}

impl DERImplicitlyTaggable for ASN1Boolean {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::BOOLEAN
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }

        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if bytes.len() != 1 {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Boolean must have length 1".to_string(), file!().to_string(), line!()));
                }
                // DER requires 0xFF for true, 0x00 for false.
                match bytes[0] {
                    0x00 => Ok(ASN1Boolean(false)),
                    0xFF => Ok(ASN1Boolean(true)),
                    _ => Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Boolean must be 0x00 or 0xFF in DER".to_string(), file!().to_string(), line!())),
                }
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "Boolean must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

// BER: BER allows any non-zero value for true.
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};

impl BERParseable for ASN1Boolean {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1Boolean::default_identifier())
    }
}

impl BERSerializable for ASN1Boolean {}

impl BERImplicitlyTaggable for ASN1Boolean {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        
         match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if bytes.len() != 1 {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Boolean must have length 1".to_string(), file!().to_string(), line!()));
                }
                match bytes[0] {
                    0x00 => Ok(ASN1Boolean(false)),
                    _ => Ok(ASN1Boolean(true)), // Any non-zero is true in BER
                }
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "Boolean must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}
