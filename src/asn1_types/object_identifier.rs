use crate::asn1_types::ASN1Identifier;
use crate::asn1::ASN1Node;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, Serializer, DERImplicitlyTaggable};
use crate::ber::{BERParseable, BERSerializable, BERImplicitlyTaggable};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ASN1ObjectIdentifier {
    bytes: Bytes,
}

impl ASN1ObjectIdentifier {
    pub fn new(components: &[u64]) -> Result<Self, ASN1Error> {
        if components.len() < 2 {
             return Err(ASN1Error::new(ErrorCode::TooFewOIDComponents, "Must have at least 2 components".to_string(), file!().to_string(), line!()));
        }
        
        let first = components[0];
        let second = components[1];
        
        if first > 2 {
             return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "First OID component must be 0, 1, or 2".to_string(), file!().to_string(), line!()));
        }
        if first < 2 && second > 39 {
             return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Second OID component must be <= 39 if first is 0 or 1".to_string(), file!().to_string(), line!()));
        }
        
        let mut buffer = Vec::new();
        let first_byte_val = first * 40 + second;
        write_oid_subidentifier(first_byte_val, &mut buffer);
        
        for &c in components[2..].iter() {
            write_oid_subidentifier(c, &mut buffer);
        }
        
        Ok(ASN1ObjectIdentifier { bytes: Bytes::from(buffer) })
    }

    pub fn oid_components(&self) -> Result<Vec<u64>, ASN1Error> {
        let mut components = Vec::new();
        let mut data = self.bytes.clone();
        
        // Read first subidentifier
        if data.is_empty() {
             return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Zero components in OID".to_string(), file!().to_string(), line!()));
        }
        
        let before_first = data.len();
        let first_val = read_oid_subidentifier(&mut data)?;
        if data.len() == before_first {
            return Err(ASN1Error::new(
                ErrorCode::InvalidASN1Object,
                "OID decoder failed to consume first subidentifier".to_string(),
                file!().to_string(),
                line!(),
            ));
        }
        
        let first = first_val / 40;
        let second = first_val % 40;
        components.push(first);
        components.push(second); // This might be wrong if first=2 and second > 39?
        // Spec: "The numerical value of the first subidentifier is derived from ... (X*40) + Y"
        // If X=2, Y can be large. So first_val can be > 119.
        // If first_val >= 80, then X=2.
        // Wait, if X=0 or 1, Y<=39. Max 79.
        // So if val < 80, X = val/40, Y = val%40.
        // If val >= 80, X = 2, Y = val - 80.
        // Let's refine.
        // Swift uses `dividingBy: 40`.
        // If first_val = 120 (2.40). 120/40 = 3. Remainder 0. -> 3.0. Wrong. X must be 0,1,2.
        
        // Correct logic:
        // if val < 80: X = val / 40, Y = val % 40.
        // if val >= 80: X = 2, Y = val - 80.
        
        // Re-checking Swift:
        // `let (firstSubcomponent, secondSubcomponent) = firstEncodedSubcomponent.quotientAndRemainder(dividingBy: 40)`
        // If `firstEncodedSubcomponent` is 120, Swift returns (3, 0).
        // Does Swift OID support X > 2?
        // RFC says: "The first octet has value 40 * value1 + value2. (This is unambiguous, since value1 is limited to 0, 1, and 2; value2 is limited to 0 to 39 when value1 is 0 or 1; and, according to X.208, n is always at least 2.)"
        // Wait, if value1=2, value2 can be anything. (2 * 40) + Y = 80 + Y.
        // If encoded is 80, 80/40 = 2, rem 0. -> 2.0. Correct.
        // If encoded is 120. 120/40 = 3. rem 0. -> 3.0. X=3? Invalid.
        
        // So Swift implementation assumes valid OID input where X encoded is correct.
        // But if I decode 120, I get 3.0.
        // If X is limited to 2, then 120 means X=2, Y=40.
        // 2*40 + 40 = 120.
        // So strictly speaking, X = min(val / 40, 2)?
        // No, if val >= 80, X is 2.
        // Implement correct logic over Swift's simple division?
        // Or assume Swift is right and I should match it?
        // Note: Swift's `oidComponents` implementation simply divides. 
        // `let (firstSubcomponent, secondSubcomponent) = firstEncodedSubcomponent.quotientAndRemainder(dividingBy: 40)`
        // This implies Swift `ASN1ObjectIdentifier` might return X=3.
        // But `init` with array checks `first > 2`.
        // So it seems passing an encoded OID that results in X=3 is possible via `derEncoded`.
        // I will stick to simple division to match Swift behavior, assuming encoded data is usually valid.
        // BUT strict OID decoding usually handles X=2 specially.
        // Given "Maximal type similarity", matching behavior (even if simplistic) is good.
        // But `ASN1ObjectIdentifier` in Swift is a struct.
        // I'll replicate Swift's logic: simple division.
        
        // But wait, if X=2, Y=40 -> 120. 120/40 = 3. 
        // This means Swift would return [3, 0].
        // Is that valid? Maybe not. But that's what the code does.
        
        // Actually, checking `ASN1ObjectIdentifier.swift`:
        // It validates in `validateObjectIdentifierInEncodedForm`. But that only checks `readUIntUsing8BitBytesASN1Discipline`.
        // It does not check range of first component.
        
        // Use Swift logic.
        
        // Fix for first component extraction from `components` vec which handles this.
        // Already pushed
        components[0] = first;
        components[1] = second;

        while !data.is_empty() {
            let before = data.len();
            components.push(read_oid_subidentifier(&mut data)?);
            if data.len() == before {
                return Err(ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "OID decoder failed to consume subidentifier bytes".to_string(),
                    file!().to_string(),
                    line!(),
                ));
            }
        }
        
        Ok(components)
    }
}

impl DERParseable for ASN1ObjectIdentifier {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, ASN1ObjectIdentifier::default_identifier())
    }
}

impl DERSerializable for ASN1ObjectIdentifier {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error> {
         serializer.append_primitive_node(Self::default_identifier(), |buf| {
             buf.extend_from_slice(&self.bytes);
             Ok(())
         })
    }
}

impl DERImplicitlyTaggable for ASN1ObjectIdentifier {
    fn default_identifier() -> ASN1Identifier {
        ASN1Identifier::OBJECT_IDENTIFIER
    }

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         if node.identifier != identifier {
             return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("Expected {}, got {}", identifier, node.identifier), file!().to_string(), line!()));
        }
        match node.content {
            crate::asn1::Content::Primitive(bytes) => {
                // Validate
                if bytes.is_empty() {
                     return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Zero components in OID".to_string(), file!().to_string(), line!()));
                }
                
                // Validate VLQ
                let mut check = bytes.clone();
                while !check.is_empty() {
                    let before = check.len();
                    read_oid_subidentifier(&mut check)?;
                    if check.len() == before {
                        return Err(ASN1Error::new(
                            ErrorCode::InvalidASN1Object,
                            "OID validation failed to consume subidentifier bytes".to_string(),
                            file!().to_string(),
                            line!(),
                        ));
                    }
                }
                
                Ok(ASN1ObjectIdentifier { bytes })
            },
             _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, "OID must be primitive".to_string(), file!().to_string(), line!()))
        }
    }
}

impl BERParseable for ASN1ObjectIdentifier {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_ber_node_with_identifier(node, ASN1ObjectIdentifier::default_identifier())
    }
}
impl BERSerializable for ASN1ObjectIdentifier {}
impl BERImplicitlyTaggable for ASN1ObjectIdentifier {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
         Self::from_der_node_with_identifier(node, identifier)
    }
}

// Helpers
fn write_oid_subidentifier(mut value: u64, buf: &mut Vec<u8>) {
    if value == 0 {
        buf.push(0);
        return;
    }

    let mut stack = Vec::with_capacity(10);
    let mut finished = false;
    for _ in 0..=10 {
        stack.push((value & 0x7F) as u8);
        value >>= 7;
        let done = value == 0;
        if done {
            finished = true;
            break;
        }
    }

    assert!(
        finished,
        "OID subidentifier requires more than 10 bytes of VLQ encoding"
    );

    for (index, byte) in stack.iter().rev().enumerate() {
        let mut out = *byte;
        if index + 1 < stack.len() {
            out |= 0x80;
        }
        buf.push(out);
    }
}

fn read_oid_subidentifier(data: &mut Bytes) -> Result<u64, ASN1Error> {
    let mut value: u64 = 0;
    let mut first_byte = true;
    loop {
        if data.is_empty() {
            return Err(ASN1Error::new(
                ErrorCode::TruncatedASN1Field,
                "".to_string(),
                file!().to_string(),
                line!(),
            ));
        }
        let byte = data.split_to(1)[0];

        if first_byte && byte == 0x80 {
            return Err(ASN1Error::new(
                ErrorCode::InvalidASN1Object,
                "OID subidentifier encoded with leading 0 byte".to_string(),
                file!().to_string(),
                line!(),
            ));
        }
        first_byte = false;

        let chunk = u64::from(byte & 0x7F);
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(chunk))
            .ok_or_else(|| {
                ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "OID subidentifier exceeds u64 capacity".to_string(),
                    file!().to_string(),
                    line!(),
                )
            })?;

        if (byte & 0x80) == 0 {
            break;
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_types::ASN1Identifier;
    use crate::ber;
    use crate::der;
    use bytes::Bytes;

    #[test]
    fn test_oid_new_errors() {
        assert!(ASN1ObjectIdentifier::new(&[1]).is_err());
        assert!(ASN1ObjectIdentifier::new(&[3, 0]).is_err());
        assert!(ASN1ObjectIdentifier::new(&[0, 41]).is_err()); // > 39
        assert!(ASN1ObjectIdentifier::new(&[1, 40]).is_err());
        
        assert!(ASN1ObjectIdentifier::new(&[0, 39]).is_ok());
        assert!(ASN1ObjectIdentifier::new(&[1, 39]).is_ok());
        assert!(ASN1ObjectIdentifier::new(&[2, 100]).is_ok());
    }


    #[test]
    fn test_whitebox_oid_leading_zero_vlq() {
        // Tag 06 Length 02 Data 80 01
        let data = vec![0x06, 0x02, 0x80, 0x01];
        let res = ASN1ObjectIdentifier::from_der_bytes(&data);
        assert!(res.is_err());
    }

    #[test]
    fn test_oid_components_empty_bytes_error() {
        let oid = ASN1ObjectIdentifier { bytes: Bytes::new() };
        assert!(oid.oid_components().is_err());
    }

    #[test]
    fn test_oid_new_zero_first_subidentifier_hits_zero_write_path() {
        // firstByteVal = 0 * 40 + 0 => write_oid_subidentifier(0, ...)
        let oid = ASN1ObjectIdentifier::new(&[0, 0]).unwrap();
        assert_eq!(oid.bytes.as_ref(), [0x00]);
        let comps = oid.oid_components().unwrap();
        assert_eq!(comps, vec![0, 0]);
    }

    #[test]
    fn test_oid_der_identifier_mismatch() {
        let node = der::parse(&[0x06, 0x01, 0x00]).unwrap();
        let res = <ASN1ObjectIdentifier as crate::der::DERImplicitlyTaggable>::from_der_node_with_identifier(
            node,
            ASN1Identifier::INTEGER,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_oid_der_empty_content_error() {
        let res = ASN1ObjectIdentifier::from_der_bytes(&[0x06, 0x00]);
        assert!(res.is_err());
    }

    #[test]
    fn test_oid_der_constructed_rejected() {
        let node = der::parse(&[0x26, 0x00]).unwrap();
        let res = ASN1ObjectIdentifier::from_der_node(node);
        assert!(res.is_err());
    }

    #[test]
    fn test_oid_ber_wrappers() {
        let node = ber::parse(&[0x06, 0x01, 0x00]).unwrap();
        let v = ASN1ObjectIdentifier::from_ber_node(node).unwrap();
        assert_eq!(v.oid_components().unwrap(), vec![0, 0]);

        let node = ber::parse(&[0x06, 0x01, 0x00]).unwrap();
        let v = <ASN1ObjectIdentifier as crate::ber::BERImplicitlyTaggable>::from_ber_node_with_identifier(
            node,
            ASN1Identifier::OBJECT_IDENTIFIER,
        )
        .unwrap();
        assert_eq!(v.oid_components().unwrap(), vec![0, 0]);

        let node = ber::parse(&[0x06, 0x01, 0x00]).unwrap();
        let res = <ASN1ObjectIdentifier as crate::ber::BERImplicitlyTaggable>::from_ber_node_with_identifier(
            node,
            ASN1Identifier::INTEGER,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_read_oid_subidentifier_empty_error() {
        let mut data = Bytes::new();
        let res = read_oid_subidentifier(&mut data);
        assert!(res.is_err());
    }

    #[test]
    fn test_write_oid_subidentifier_encodes_multibyte_values() {
        let mut buf = Vec::new();
        write_oid_subidentifier(200, &mut buf);
        assert_eq!(buf, vec![0x81, 0x48], "expected continuation bit only on first byte");
    }

    #[test]
    fn test_read_oid_subidentifier_round_trip_large_value() {
        let mut buf = Vec::new();
        write_oid_subidentifier(9_876_543, &mut buf);
        let mut bytes = Bytes::from(buf.clone());
        let parsed = read_oid_subidentifier(&mut bytes).unwrap();
        assert_eq!(parsed, 9_876_543);
        assert!(bytes.is_empty());
        assert_eq!(buf.last().unwrap() & 0x80, 0);
        assert!(buf[..buf.len() - 1].iter().all(|b| b & 0x80 != 0));
    }

    #[test]
    fn test_read_oid_subidentifier_accepts_max_pre_shift_value() {
        let limit = u64::MAX / 128;
        let mut buf = Vec::new();
        write_oid_subidentifier(limit, &mut buf);
        let mut bytes = Bytes::from(buf);
        let parsed = read_oid_subidentifier(&mut bytes).unwrap();
        assert_eq!(parsed, limit);
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_read_oid_subidentifier_rejects_leading_zero_encoding() {
        let mut data = Bytes::from_static(&[0x80, 0x01]);
        let err = read_oid_subidentifier(&mut data).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidASN1Object);
    }

    #[test]
    fn test_read_oid_subidentifier_overflow_detected() {
        let mut encoded = vec![0xFF; 10];
        encoded.push(0x7F);
        let mut data = Bytes::from(encoded);
        let err = read_oid_subidentifier(&mut data).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidASN1Object);
    }
}
