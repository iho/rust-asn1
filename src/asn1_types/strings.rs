use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};

macro_rules! impl_string_type {
    ($name:ident, $tag:expr, $validation:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: String) -> Result<Self, ASN1Error> {
                if !($validation)(&s) {
                    return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, format!("Invalid content for {}", stringify!($name)), file!().to_string(), line!()));
                }
                Ok($name(s))
            }
        }

        impl From<$name> for String {
             fn from(val: $name) -> Self { val.0 }
        }

        impl DERParseable for $name {
            fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
                Self::from_der_node_with_identifier(node, $name::default_identifier())
            }
        }

        impl DERSerializable for $name {
            fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
                serializer.append_primitive_node(Self::default_identifier(), |buf| {
                    buf.extend_from_slice(self.0.as_bytes());
                    Ok(())
                })
            }
        }

        impl DERImplicitlyTaggable for $name {
            fn default_identifier() -> ASN1Identifier {
                $tag
            }

            fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
                 if node.identifier != identifier {
                     return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
                }
                match node.content {
                    crate::asn1::Content::Primitive(bytes) => {
                        let s = String::from_utf8(bytes.to_vec()).map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTF-8".to_string(), file!().to_string(), line!()))?;
                        if !($validation)(&s) {
                             return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, format!("Invalid content for {}", stringify!($name)), file!().to_string(), line!()));
                        }
                        Ok($name(s))
                    },
                     _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("{} must be primitive", stringify!($name)), file!().to_string(), line!()))
                }
            }
        }
        
        impl BERParseable for $name {
             fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
                  Self::from_ber_node_with_identifier(node, $name::default_identifier())
             }
        }
        impl BERSerializable for $name {}
        impl BERImplicitlyTaggable for $name {
             fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
                  // BER allows constructed strings?
                  // Swift implementation supports constructed strings by concatenating.
                  
                  if node.identifier != identifier {
                     return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
                  }
                  match node.content {
                     crate::asn1::Content::Primitive(bytes) => {
                         let s = String::from_utf8(bytes.to_vec()).map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTF-8".to_string(), file!().to_string(), line!()))?;
                         if !($validation)(&s) {
                                return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, format!("Invalid content for {}", stringify!($name)), file!().to_string(), line!()));
                         }
                         Ok($name(s))
                     },
                     crate::asn1::Content::Constructed(collection) => {
                         let mut res = String::new();
                         for child in collection {
                             let part = $name::from_ber_node(child)?;
                             res.push_str(&part.0);
                         }
                         Ok($name(res))
                     }
                  }
             }
        }
    };
}

impl_string_type!(ASN1UTF8String, ASN1Identifier::UTF8_STRING, |_s: &str| true); // UTF-8 check done by String::from_utf8
impl_string_type!(ASN1PrintableString, ASN1Identifier::PRINTABLE_STRING, |s: &str| {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?')
    })
});
impl_string_type!(ASN1IA5String, ASN1Identifier::IA5_STRING, |s: &str| s.is_ascii());
impl_string_type!(ASN1NumericString, ASN1Identifier::NUMERIC_STRING, |s: &str| s.chars().all(|c| c.is_ascii_digit() || c == ' '));

// Teletex, Videotex, Graphics, etc?
// Implement as needed. These are the commons.
