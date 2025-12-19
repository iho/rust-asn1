use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime, Datelike};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeneralizedTime(pub DateTime<Utc>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UTCTime(pub DateTime<Utc>);

impl From<DateTime<Utc>> for GeneralizedTime {
    fn from(dt: DateTime<Utc>) -> Self { GeneralizedTime(dt) }
}
impl From<DateTime<Utc>> for UTCTime {
    fn from(dt: DateTime<Utc>) -> Self { UTCTime(dt) }
}

impl DERParseable for GeneralizedTime {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, GeneralizedTime::default_identifier())
    }
}

impl DERSerializable for GeneralizedTime {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
         // Format: YYYYMMDDHHMMSSZ
         // DER requires Z (UTC).
         let s = self.0.format("%Y%m%d%H%M%SZ").to_string();
         serializer.append_primitive_node(Self::default_identifier(), |buf| {
             buf.extend_from_slice(s.as_bytes());
             Ok(())
         })
    }
}

impl DERImplicitlyTaggable for GeneralizedTime {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::GENERALIZED_TIME
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                let s = String::from_utf8(bytes.to_vec()).map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTF-8".to_string(), file!().to_string(), line!()))?;
                // Parse GeneralizedTime
                // Basic format: YYYYMMDDHHMMSSZ
                // Or with fractional seconds.
                // Or with offset.
                // DER requires Z.
                if !s.ends_with('Z') {
                     return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, "GeneralizedTime must end with Z in DER".to_string(), file!().to_string(), line!()));
                }
                
                // Keep it simple: try %Y%m%d%H%M%SZ.
                // Fractional not implemented for now to save space/time, strictly adhering to what usually appears.
                // If parsing fails, error.
                // Use NaiveDateTime then assume UTC
                let naive = NaiveDateTime::parse_from_str(&s, "%Y%m%d%H%M%SZ").map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid GeneralizedTime format".to_string(), file!().to_string(), line!()))?;
                let dt = Utc.from_utc_datetime(&naive);
                Ok(GeneralizedTime(dt))
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "GeneralizedTime must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}


impl DERParseable for UTCTime {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, UTCTime::default_identifier())
    }
}

impl DERSerializable for UTCTime {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
         // Format: YYMMDDHHMMSSZ
         let s = self.0.format("%y%m%d%H%M%SZ").to_string();
         serializer.append_primitive_node(Self::default_identifier(), |buf| {
             buf.extend_from_slice(s.as_bytes());
             Ok(())
         })
    }
}

impl DERImplicitlyTaggable for UTCTime {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::UTC_TIME
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                let s = String::from_utf8(bytes.to_vec()).map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTF-8".to_string(), file!().to_string(), line!()))?;
                if !s.ends_with('Z') {
                     return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, "UTCTime must end with Z in DER".to_string(), file!().to_string(), line!()));
                }
                
                // Parse YYMMDDHHMMSSZ
                // We need to handle windowing.
                // Scan year first.
                if s.len() < 2 {
                      return Err(ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTCTime length".to_string(), file!().to_string(), line!()));
                }
                
                let naive = NaiveDateTime::parse_from_str(&s, "%y%m%d%H%M%SZ").map_err(|_| ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid UTCTime format".to_string(), file!().to_string(), line!()))?;
                
                // chrono %y parses 1969-2068 logic.
                // ASN.1 logic: 0..49 -> 2000..2049. 50..99 -> 1950..1999.
                // Chrono's logic for %y matches this mostly (splits at 69).
                // "The range of the year logic in chrono needs verification or custom logic."
                // Chrono docs say: "00-68 maps to 2000-2068, 69-99 maps to 1969-1999".
                // ASN.1 wants split at 50.
                
                let year_str = &s[0..2];
                let year_val: i32 = year_str.parse().unwrap_or(0);
                
                let century = if year_val >= 50 { 1900 } else { 2000 };
                let full_year = century + year_val;
                
                // Construct DateTime with this year.
                // naive has parsed year already with chrono logic. We correct it.
                let corrected_naive = naive.with_year(full_year).ok_or(ASN1Error::new(ErrorCode::InvalidStringRepresentation, "Invalid year".to_string(), file!().to_string(), line!()))?;
                
                Ok(UTCTime(Utc.from_utc_datetime(&corrected_naive)))
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "UTCTime must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

// BER implementations
impl BERParseable for GeneralizedTime {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> { Self::from_der_node(node) }
}
impl BERSerializable for GeneralizedTime {}
impl BERImplicitlyTaggable for GeneralizedTime {
     fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> { Self::from_der_node_with_identifier(node, identifier) }
}

impl BERParseable for UTCTime {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> { Self::from_der_node(node) }
}
impl BERSerializable for UTCTime {}
impl BERImplicitlyTaggable for UTCTime {
     fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> { Self::from_der_node_with_identifier(node, identifier) }
}
