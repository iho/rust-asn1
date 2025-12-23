use crate::asn1::ASN1Node;
use crate::asn1_types::ASN1Identifier;
use crate::der::{DERImplicitlyTaggable, DERParseable, DERSerializable, Serializer};
use crate::errors::{ASN1Error, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ASN1Real(pub f64);

impl From<f64> for ASN1Real {
    fn from(v: f64) -> Self {
        ASN1Real(v)
    }
}

impl From<ASN1Real> for f64 {
    fn from(val: ASN1Real) -> Self {
        val.0
    }
}

impl DERParseable for ASN1Real {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1Real::default_identifier())
    }
}

impl DERSerializable for ASN1Real {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
        serializer.append_primitive_node(Self::default_identifier(), |buf| {
            // Handle special cases
            if self.0 == 0.0 {
                // Zero is encoded as zero-length content
                return Ok(());
            }

            if self.0.is_infinite() {
                // Positive infinity: 0x40
                // Negative infinity: 0x41
                buf.push(if self.0.is_sign_positive() {
                    0x40
                } else {
                    0x41
                });
                return Ok(());
            }

            if self.0.is_nan() {
                // NaN not supported in DER
                return Err(ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "NaN cannot be encoded in DER REAL".to_string(),
                    file!().to_string(),
                    line!(),
                ));
            }

            // Binary encoding (IEEE 754 double)
            // Format: 0x80 | sign_bit | exponent_length | mantissa
            let bits = self.0.to_bits();
            let sign = ((bits >> 63) & 1) as u8;
            let exponent = ((bits >> 52) & 0x7FF) as i16 - 1023;
            let mantissa = bits & 0x000FFFFFFFFFFFFF;

            // First octet: binary encoding, base 2
            buf.push(0x80 | (sign << 6));

            // Exponent (minimal encoding)
            if exponent >= -128 && exponent <= 127 {
                buf.push(exponent as u8);
            } else {
                buf.push(((exponent >> 8) & 0xFF) as u8);
                buf.push((exponent & 0xFF) as u8);
            }

            // Mantissa (remove trailing zeros)
            let mantissa_bytes = mantissa.to_be_bytes();
            let mut last_nonzero = 7;
            while last_nonzero > 0 && mantissa_bytes[last_nonzero] == 0 {
                last_nonzero -= 1;
            }
            buf.extend_from_slice(&mantissa_bytes[0..=last_nonzero]);

            Ok(())
        })
    }
}

impl DERImplicitlyTaggable for ASN1Real {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::REAL
    }

    fn from_der_node_with_identifier(
        node: ASN1Node,
        identifier: ASN1Identifier,
    ) -> Result<Self, ASN1Error> {
        if node.identifier != identifier {
            return Err(ASN1Error::new(
                ErrorCode::UnexpectedFieldType,
                format!("Expected {}, got {}", identifier, node.identifier),
                file!().to_string(),
                line!(),
            ));
        }

        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                // Zero-length means zero
                if bytes.is_empty() {
                    return Ok(ASN1Real(0.0));
                }

                let first = bytes[0];

                // Special values
                if first == 0x40 {
                    return Ok(ASN1Real(f64::INFINITY));
                }
                if first == 0x41 {
                    return Ok(ASN1Real(f64::NEG_INFINITY));
                }

                // Binary encoding
                if (first & 0x80) != 0 {
                    let sign = if (first & 0x40) != 0 { -1.0 } else { 1.0 };
                    let exp_len = ((first & 0x03) + 1) as usize;

                    if bytes.len() < 1 + exp_len {
                        return Err(ASN1Error::new(
                            ErrorCode::InvalidASN1Object,
                            "REAL encoding too short".to_string(),
                            file!().to_string(),
                            line!(),
                        ));
                    }

                    // Read exponent
                    let mut exponent: i64 = 0;
                    for i in 0..exp_len {
                        exponent = (exponent << 8) | (bytes[1 + i] as i64);
                    }
                    // Sign extend
                    if bytes[1] & 0x80 != 0 {
                        exponent |= !0i64 << (exp_len * 8);
                    }

                    // Read mantissa
                    let mut mantissa: u64 = 0;
                    for &byte in &bytes[1 + exp_len..] {
                        mantissa = (mantissa << 8) | (byte as u64);
                    }

                    // Reconstruct IEEE 754
                    let value = sign * (mantissa as f64) * 2.0f64.powi(exponent as i32);
                    return Ok(ASN1Real(value));
                }

                // Decimal encoding not supported for now
                Err(ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "Decimal REAL encoding not supported".to_string(),
                    file!().to_string(),
                    line!(),
                ))
            }
            _ => Err(ASN1Error::new(
                ErrorCode::UnexpectedFieldType,
                "REAL must be primitive".to_string(),
                file!().to_string(),
                line!(),
            )),
        }
    }
}

// BER support (same as DER for REAL)
use crate::ber::{BERImplicitlyTaggable, BERParseable, BERSerializable};

impl BERParseable for ASN1Real {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1Real::default_identifier())
    }
}

impl BERSerializable for ASN1Real {}

impl BERImplicitlyTaggable for ASN1Real {
    fn from_ber_node_with_identifier(
        node: ASN1Node,
        identifier: ASN1Identifier,
    ) -> Result<Self, ASN1Error> {
        // BER allows same encoding as DER for REAL
        Self::from_der_node_with_identifier(node, identifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_zero() {
        let real = ASN1Real(0.0);
        let mut serializer = Serializer::new();
        real.serialize(&mut serializer).unwrap();
        // Zero should be encoded as zero-length
    }

    #[test]
    fn test_real_infinity() {
        let pos_inf = ASN1Real(f64::INFINITY);
        let neg_inf = ASN1Real(f64::NEG_INFINITY);
        let mut serializer = Serializer::new();
        pos_inf.serialize(&mut serializer).unwrap();
        neg_inf.serialize(&mut serializer).unwrap();
    }
}
