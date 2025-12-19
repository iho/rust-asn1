use crate::asn1::{ASN1Node, ASN1NodeCollection, ASN1NodeCollectionIterator, EncodingRules, ParseResult};
use crate::asn1_types::ASN1Identifier;
use crate::errors::{ASN1Error, ErrorCode};
use bytes::{BufMut, Bytes, BytesMut};

pub trait DERParseable: Sized {
    fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error>;

    fn from_der_iterator(iter: &mut ASN1NodeCollectionIterator) -> Result<Self, ASN1Error> {
        let node = iter.next().ok_or_else(|| ASN1Error::new(
            ErrorCode::InvalidASN1Object,
            format!("Unable to decode {}, no ASN.1 nodes to decode", std::any::type_name::<Self>()),
            file!().to_string(),
            line!(),
        ))?;
        Self::from_der_node(node)
    }

    fn from_der_bytes(bytes: &[u8]) -> Result<Self, ASN1Error> {
         let node = parse(bytes)?;
         Self::from_der_node(node)
    }
}

pub trait DERSerializable {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), ASN1Error>;
}

pub trait DERImplicitlyTaggable: DERParseable + DERSerializable {
    fn default_identifier() -> ASN1Identifier;

    fn from_der_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error>;
}

// DER namespace functions

pub fn parse(data: &[u8]) -> Result<ASN1Node, ASN1Error> {
    let bytes = Bytes::copy_from_slice(data);
    let result = ParseResult::parse(bytes, EncodingRules::Distinguished)?;

    let first = result
        .nodes
        .first()
        .ok_or_else(|| {
            ASN1Error::new(
                ErrorCode::InvalidASN1Object,
                "No ASN.1 nodes parsed".to_string(),
                file!().to_string(),
                line!(),
            )
        })?
        .clone();

    let nodes_arc = std::sync::Arc::new(result.nodes);
    let root_depth = first.depth;

    // Verify single root
    let end_index = nodes_arc
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, node)| node.depth <= root_depth)
        .map(|(idx, _)| idx)
        .unwrap_or(nodes_arc.len());

    if end_index != nodes_arc.len() {
        return Err(ASN1Error::new(
            ErrorCode::InvalidASN1Object,
            "ASN1ParseResult unexpectedly allowed multiple root nodes".to_string(),
            file!().to_string(),
            line!(),
        ));
    }

    if first.is_constructed {
        let collection = ASN1NodeCollection::new(nodes_arc, 1..end_index, root_depth);
        Ok(ASN1Node {
            identifier: first.identifier,
            content: crate::asn1::Content::Constructed(collection),
            encoded_bytes: first.encoded_bytes,
        })
    } else {
        Ok(ASN1Node {
            identifier: first.identifier,
            content: crate::asn1::Content::Primitive(first.data_bytes.unwrap()),
            encoded_bytes: first.encoded_bytes,
        })
    }
}

pub fn sequence<T, F>(node: ASN1Node, identifier: ASN1Identifier, builder: F) -> Result<T, ASN1Error>
where
    F: FnOnce(&mut ASN1NodeCollectionIterator) -> Result<T, ASN1Error>,
{
    if node.identifier != identifier {
         return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("{}", node.identifier), file!().to_string(), line!()));
    }
    match node.content {
        crate::asn1::Content::Constructed(collection) => {
            let mut iter = collection.into_iter();
            let result = builder(&mut iter)?;
            if iter.next().is_some() {
                 return Err(ASN1Error::new(ErrorCode::InvalidASN1Object, "Unconsumed sequence nodes".to_string(), file!().to_string(), line!()));
            }
            Ok(result)
        },
        _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("{}", node.identifier), file!().to_string(), line!()))
    }
}

pub fn sequence_of<T: DERParseable>(identifier: ASN1Identifier, root_node: ASN1Node) -> Result<Vec<T>, ASN1Error> {
     if root_node.identifier != identifier {
         return Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("{}", root_node.identifier), file!().to_string(), line!()));
    }
    match root_node.content {
        crate::asn1::Content::Constructed(collection) => {
             collection.into_iter().map(|n| T::from_der_node(n)).collect()
        }
         _ => Err(ASN1Error::new(ErrorCode::UnexpectedFieldType, format!("{}", root_node.identifier), file!().to_string(), line!()))
    }
}


pub struct Serializer {
    buffer: BytesMut,
}

impl Serializer {
    pub fn new() -> Self {
        Serializer {
            buffer: BytesMut::with_capacity(1024),
        }
    }
    
    pub fn serialized_bytes(&self) -> Bytes {
        self.buffer.clone().freeze()
    }
    
    pub fn append_primitive_node(&mut self, identifier: ASN1Identifier, content_writer: impl FnOnce(&mut Vec<u8>) -> Result<(), ASN1Error>) -> Result<(), ASN1Error> {
        // identifier
        let mut temp_vec = Vec::new();
        temp_vec.write_identifier(identifier, false);
        self.buffer.put_slice(&temp_vec);
        
        // content
        let mut content = Vec::new(); // or reuse buffer?
        // length need to be calculated after content write.
        content_writer(&mut content)?;
        
        // length
        let len_bytes = encode_length(content.len());
        self.buffer.put_slice(&len_bytes);
        self.buffer.put_slice(&content);
        
        Ok(())
    }
    
    pub fn serialize<T: DERSerializable>(&mut self, node: &T) -> Result<(), ASN1Error> {
        node.serialize(self)
    }
}


// Helpers
pub(crate) trait IdentfierWriter {
    fn write_identifier(&mut self, identifier: ASN1Identifier, constructed: bool);
}

impl IdentfierWriter for Vec<u8> {
    fn write_identifier(&mut self, identifier: ASN1Identifier, constructed: bool) {
         if let Some(mut short) = identifier.short_form() {
             if constructed {
                 short |= 0x20;
             }
             self.push(short);
         } else {
             let mut top_byte = 0x1f;
             if constructed {
                 top_byte |= 0x20;
             }
             top_byte |= identifier.tag_class.top_byte_flags();
             self.push(top_byte);
             
             // base 128 encoding of tag number
             write_asn1_discipline_uint(self, identifier.tag_number);
         }
    }
}

fn write_asn1_discipline_uint(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        v.push(0);
        return;
    }
    
    let mut bytes = Vec::new();
    while n != 0 {
        bytes.push((n & 0x7F) as u8);
        n >>= 7;
    }
    
    for (i, b) in bytes.iter().rev().enumerate() {
        let mut byte = *b;
        if i != bytes.len() - 1 {
            byte |= 0x80;
        }
        v.push(byte);
    }
}

fn encode_length(len: usize) -> Vec<u8> {
    if len <= 0x7F {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut l = len;
        while l != 0 {
            bytes.push((l & 0xFF) as u8);
            l >>= 8;
        }
        let len_len = bytes.len() as u8;
        let indicator = 0x80u8 + len_len;
        let mut result = Vec::with_capacity(1 + bytes.len());
        result.push(indicator);
        for b in bytes.iter().rev() {
            result.push(*b);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_types::{ASN1Integer, ASN1Identifier, TagClass};
    use num_traits::ToPrimitive;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Dummy(u8);

    impl DERParseable for Dummy {
        fn from_der_node(node: ASN1Node) -> Result<Self, ASN1Error> {
            match node.content {
                crate::asn1::Content::Primitive(bytes) => Ok(Dummy(bytes[0])),
                _ => Err(ASN1Error::new(
                    ErrorCode::UnexpectedFieldType,
                    "".to_string(),
                    file!().to_string(),
                    line!(),
                )),
            }
        }
    }

    #[test]
    fn test_der_sequence_unconsumed() {
        let data = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let node = parse(&data).unwrap();
        
        let res: Result<(), _> = sequence(node, ASN1Identifier::SEQUENCE, |_iter| {
            Ok(())
        });
        
        assert!(res.is_err());
    }

    #[test]
    fn test_der_sequence_mismatch_identifier() {
        let data = vec![0x30, 0x00];
        let node = parse(&data).unwrap();
        
        let res: Result<(), _> = sequence(node, ASN1Identifier::SET, |_iter| {
            Ok(())
        });
        
        assert!(res.is_err());
    }

    #[test]
    fn test_der_sequence_of_mismatch() {
        let data = vec![0x30, 0x00];
        let node = parse(&data).unwrap();
        let res = sequence_of::<ASN1Integer>(ASN1Identifier::SET, node);
        assert!(res.is_err());
    }

    #[test]
    fn test_der_sequence_of_success() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let node = parse(&data).unwrap();
        let values = sequence_of::<ASN1Integer>(ASN1Identifier::SEQUENCE, node).unwrap();
        let numbers: Vec<i64> = values
            .into_iter()
            .map(|v| v.value.to_i64().unwrap())
            .collect();
        assert_eq!(numbers, vec![1, 2]);
    }

    #[test]
    fn test_identifier_writing_edge_cases() {
        let mut buf = Vec::new();
        // Tag 31 (Context Specific) -> requires long form because 31 is the marker (0x1F)
        let id = ASN1Identifier::new(31, TagClass::ContextSpecific); 
        
        buf.write_identifier(id, false);
        // Header: Context(0x80) | 0x1F = 0x9F.
        // Value: 31 (0x1F).
        assert_eq!(buf, vec![0x9F, 0x1F]);
        
        // Constructed
        buf.clear();
        buf.write_identifier(id, true);
        // Header: Context(0x80) | Constructed(0x20) | 0x1F = 0xBF.
        assert_eq!(buf, vec![0xBF, 0x1F]);
    }

    #[test]
    fn test_der_from_der_iterator_empty_error() {
        let data = vec![0x30, 0x00];
        let node = parse(&data).unwrap();
        let res: Result<(), _> = sequence(node, ASN1Identifier::SEQUENCE, |iter| {
            let _ = Dummy::from_der_iterator(iter)?;
            Ok(())
        });
        assert!(res.is_err());
    }

    #[test]
    fn test_der_sequence_non_constructed_error() {
        let node = ASN1Node {
            identifier: ASN1Identifier::SEQUENCE,
            content: crate::asn1::Content::Primitive(Bytes::from_static(&[])),
            encoded_bytes: Bytes::new(),
        };
        let res: Result<(), _> = sequence(node, ASN1Identifier::SEQUENCE, |_iter| Ok(()));
        assert!(res.is_err());
    }

    #[test]
    fn test_der_sequence_of_non_constructed_error() {
        let node = ASN1Node {
            identifier: ASN1Identifier::SEQUENCE,
            content: crate::asn1::Content::Primitive(Bytes::from_static(&[])),
            encoded_bytes: Bytes::new(),
        };
        let res = sequence_of::<ASN1Integer>(ASN1Identifier::SEQUENCE, node);
        assert!(res.is_err());
    }

    #[test]
    fn test_identifier_writing_short_constructed() {
        let mut buf = Vec::new();
        buf.write_identifier(ASN1Identifier::BOOLEAN, true);
        assert_eq!(buf, vec![0x21]);
    }

    #[test]
    fn test_write_asn1_discipline_uint_zero() {
        let mut buf = Vec::new();
        write_asn1_discipline_uint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn test_encode_length_long_form_128() {
        let mut serializer = Serializer::new();
        serializer
            .append_primitive_node(ASN1Identifier::OCTET_STRING, |buf| {
                buf.extend_from_slice(&vec![0u8; 128]);
                Ok(())
            })
            .unwrap();
        let out = serializer.serialized_bytes();
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x81);
        assert_eq!(out[2], 0x80);
    }

    #[test]
    fn test_encode_length_long_form_256() {
        let mut serializer = Serializer::new();
        serializer
            .append_primitive_node(ASN1Identifier::OCTET_STRING, |buf| {
                buf.extend_from_slice(&vec![0u8; 256]);
                Ok(())
            })
            .unwrap();
        let out = serializer.serialized_bytes();
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x82);
        assert_eq!(out[2], 0x01);
        assert_eq!(out[3], 0x00);
    }

    #[test]
    fn test_encode_length_long_form_large_value() {
        let encoded = encode_length(0x012345);
        assert_eq!(encoded, vec![0x83, 0x01, 0x23, 0x45]);
        assert_eq!(encoded[0] & 0x80, 0x80, "long-form indicator bit must be set");
    }

    #[test]
    fn test_write_large_tag() {
        // Tag 128 (Universal)
        let mut buf = Vec::new();
        let id = ASN1Identifier::new(128, TagClass::Universal);
        buf.write_identifier(id, false);
        // Header: Universal(0) | 0x1F = 0x1F.
        // Value: 128 -> 0x81 0x00.
        assert_eq!(buf, vec![0x1F, 0x81, 0x00]);
    }

    #[test]
    fn test_der_serializer_append() {
        let mut serializer = Serializer::new();
        serializer.append_primitive_node(ASN1Identifier::INTEGER, |_buf| {
            // Write nothing
            Ok(())
        }).unwrap();
        // Tag INTEGER (02) | Length 00.
        assert_eq!(serializer.serialized_bytes(), vec![0x02, 0x00]);
    }
}
