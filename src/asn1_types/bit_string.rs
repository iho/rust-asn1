use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ASN1BitString {
    pub bytes: Bytes,
    pub padding_bits: u8,
}

impl ASN1BitString {
    pub fn new(bytes: Bytes, padding_bits: u8) -> Result<Self, ASN1Error> {
        if padding_bits > 7 {
             return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Invalid padding bits > 7".to_string(), file!().to_string(), line!()));
        }
        if bytes.is_empty() && padding_bits != 0 {
             return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Empty BitString must have 0 padding bits".to_string(), file!().to_string(), line!()));
        }
        Ok(ASN1BitString { bytes, padding_bits })
    }
}

impl DERParseable for ASN1BitString {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1BitString::default_identifier())
    }
}

impl DERSerializable for ASN1BitString {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
         serializer.append_primitive_node(Self::default_identifier(), |buf| {
             buf.push(self.padding_bits);
             buf.extend_from_slice(&self.bytes);
             Ok(())
         })
    }
}

impl DERImplicitlyTaggable for ASN1BitString {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::BIT_STRING
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if bytes.is_empty() {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Empty BIT STRING content (missing padding byte)".to_string(), file!().to_string(), line!()));
                }
                let padding_bits = bytes[0];
                if padding_bits > 7 {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Invalid padding bits in BIT STRING".to_string(), file!().to_string(), line!()));
                }
                
                let data = bytes.slice(1..);
                if data.is_empty() && padding_bits != 0 {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Empty BIT STRING with non-zero padding".to_string(), file!().to_string(), line!()));
                }
                
                // DER requirement: unused bits must be zero
                if !data.is_empty() {
                    let last = data[data.len() - 1];
                    let mask = (1u8 << padding_bits) - 1;
                    if (last & mask) != 0 {
                        return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "BIT STRING unused bits must be zero".to_string(), file!().to_string(), line!()));
                    }
                }

                Ok(ASN1BitString { bytes: data, padding_bits })
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "DER BIT STRING must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

impl BERParseable for ASN1BitString {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1BitString::default_identifier())
    }
}
impl BERSerializable for ASN1BitString {}
impl BERImplicitlyTaggable for ASN1BitString {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
             crate::asn1::Content::Primitive(bytes) => {
                 // Reuse DER logic but relax unused bits check?
                 // BER allows non-zero unused bits but it's weird.
                 // We will conform to extracting implementation.
                 if bytes.is_empty() {
                      return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Empty BIT STRING content".to_string(), file!().to_string(), line!()));
                 }
                 let padding_bits = bytes[0];
                 if padding_bits > 7 {
                       return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Invalid padding bits".to_string(), file!().to_string(), line!()));
                 }
                 Ok(ASN1BitString { bytes: bytes.slice(1..), padding_bits })
             },
             crate::asn1::Content::Constructed(_collection) => {
                 // BER allows constructed BIT STRING
                 Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Constructed BIT STRING not implemented yet".to_string(), file!().to_string(), line!()))
             }
        }
    }
}
