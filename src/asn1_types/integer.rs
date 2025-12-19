use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use num_bigint::BigInt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ASN1Integer {
    pub value: BigInt,
}

impl From<i64> for ASN1Integer {
    fn from(v: i64) -> Self {
        ASN1Integer { value: BigInt::from(v) }
    }
}

impl From<BigInt> for ASN1Integer {
    fn from(v: BigInt) -> Self {
        ASN1Integer { value: v }
    }
}

impl DERParseable for ASN1Integer {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1Integer::default_identifier())
    }
}

impl DERSerializable for ASN1Integer {
     fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
        serializer.append_primitive_node(Self::default_identifier(), |buf| {
            let bytes = self.value.to_signed_bytes_be();
            buf.extend_from_slice(&bytes);
            Ok(())
        })
    }
}

impl DERImplicitlyTaggable for ASN1Integer {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::INTEGER
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }

        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if bytes.is_empty() {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Integer with 0 bytes".to_string(), file!().to_string(), line!()));
                }
                
                // DER requires minimal encoding
                // If len > 1:
                // if bytes[0] == 0x00 and bytes[1] & 0x80 == 0 { error } (leading zero that is redundant)
                // if bytes[0] == 0xFF and bytes[1] & 0x80 == 0x80 { error } (leading FF that is redundant)
                
                if bytes.len() > 1 {
                    let first = bytes[0];
                    let second = bytes[1];
                    if first == 0x00 {
                        if (second & 0x80) == 0 {
                            return Err(ASN1Error::new(
                                ErrorCode::InvalidASN1IntegerEncoding,
                                "Integer encoded with redundant leading zero".to_string(),
                                file!().to_string(),
                                line!(),
                            ));
                        }
                    } else if first == 0xFF {
                        if (second & 0x80) == 0x80 {
                            return Err(ASN1Error::new(
                                ErrorCode::InvalidASN1IntegerEncoding,
                                "Integer encoded with redundant leading FF".to_string(),
                                file!().to_string(),
                                line!(),
                            ));
                        }
                    }
                }
                
                let val = BigInt::from_signed_bytes_be(&bytes);
                Ok(ASN1Integer { value: val })
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "Integer must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

// BER: BER allows non-minimal encoding? Swift BER.swift defers to DER for `explicitlyTagged` etc, but `BERParseable` for Integer?
// Swift `ASN1Integer` conforms to `BERImplicitlyTaggable`.
// It implements `init(berEncoded:withIdentifier:)` which allows non-minimal.

use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};

impl BERParseable for ASN1Integer {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1Integer::default_identifier())
    }
}

impl BERSerializable for ASN1Integer {}

impl BERImplicitlyTaggable for ASN1Integer {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        
         match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                if bytes.is_empty() {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Integer with 0 bytes".to_string(), file!().to_string(), line!()));
                }
                // BER allows redundant bytes.
                let val = BigInt::from_signed_bytes_be(&bytes);
                Ok(ASN1Integer { value: val })
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "Integer must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}
