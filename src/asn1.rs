use crate::asn1_types::{ASN1Identifier, TagClass};
use crate::errors::{ASN1Error, ErrorCode};
use bytes::Bytes;
use std::sync::Arc;
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingRules {
    Basic,
    Distinguished,
}

fn minimal_octet_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let significant_bits = 64 - value.leading_zeros();
    ((significant_bits + 7) / 8) as usize
}

impl EncodingRules {
    pub fn indefinite_length_allowed(&self) -> bool {
        matches!(self, EncodingRules::Basic)
    }

    pub fn non_minimal_encoded_lengths_allowed(&self) -> bool {
        matches!(self, EncodingRules::Basic)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParserNode {
    pub identifier: ASN1Identifier,
    pub depth: usize,
    pub is_constructed: bool,
    pub encoded_bytes: Bytes,
    pub data_bytes: Option<Bytes>,
}

impl ParserNode {
    pub fn is_end_marker(&self) -> bool {
        self.identifier.tag_class == TagClass::Universal
            && self.identifier.tag_number == 0
            && !self.is_constructed
            && self.encoded_bytes.len() == 2
            && self.encoded_bytes.as_ref() == [0x00, 0x00]
    }
}

#[derive(Debug)]
pub(crate) struct ParseResult {
    pub nodes: Vec<ParserNode>,
}

impl ParseResult {
    const MAXIMUM_NODE_DEPTH: usize = 50;

    pub fn parse(data: Bytes, rules: EncodingRules) -> Result<ParseResult, ASN1Error> {
        let mut nodes = Vec::with_capacity(16);
        let mut current_data = data;
        
        Self::_parse_node(&mut current_data, rules, 1, &mut nodes)?;
        
        if !current_data.is_empty() {
             return Err(ASN1Error::new(
                ErrorCode::InvalidASN1Object,
                "Trailing unparsed data is present".to_string(),
                file!().to_string(),
                line!(),
            ));
        }

        Ok(ParseResult { nodes })
    }

    fn _parse_node(
        data: &mut Bytes,
        rules: EncodingRules,
        depth: usize,
        nodes: &mut Vec<ParserNode>,
    ) -> Result<(), ASN1Error> {
        if depth > Self::MAXIMUM_NODE_DEPTH {
            return Err(ASN1Error::new(
                ErrorCode::InvalidASN1Object,
                "Excessive stack depth was reached".to_string(),
                file!().to_string(),
                line!(),
            ));
        }

        if data.is_empty() {
             return Err(ASN1Error::new(
                ErrorCode::TruncatedASN1Field,
                "".to_string(),
                file!().to_string(),
                line!(),
            ));
        }

        let original_data = data.clone();
        let raw_identifier = data.split_to(1)[0];

        let constructed = (raw_identifier & 0x20) != 0;
        let identifier: ASN1Identifier;

        if (raw_identifier & 0x1f) == 0x1f {
            let tag_class = TagClass::from_top_byte(raw_identifier);
            // Read UInt... implementation needed (readUIntUsing8BitBytesASN1Discipline)
            // For now simple implementation or need helper.
            // Assuming short tag for simplicity sake or I need to implement read_uint...
            // Implementing logic inline for now:
            let (tag_number, _bytes_read) = read_asn1_discipline_uint(data)?;
             if tag_number < 0x1f {
                 return Err(ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    format!("ASN.1 tag incorrectly encoded in long form: {}", tag_number),
                    file!().to_string(),
                    line!(),
                ));
            }
            identifier = ASN1Identifier::new(tag_number, tag_class);
        } else {
            identifier = ASN1Identifier::from_short_identifier(raw_identifier);
        }

        let wide_length = _read_asn1_length(data, !rules.non_minimal_encoded_lengths_allowed())?;
        
        match wide_length {
            ASN1Length::Definite(length) => {
                 let length_usize = length as usize;
                 if data.len() < length_usize {
                     return Err(ASN1Error::new(
                        ErrorCode::TruncatedASN1Field,
                        "".to_string(),
                        file!().to_string(),
                        line!(),
                    ));
                 }
                 
                 let sub_data = data.split_to(length_usize);
                 // encoded_bytes is original_data[0 .. (header + length)]
                 let total_len = original_data.len() - data.len(); 
                 let encoded_bytes = original_data.slice(0..total_len);

                 if constructed {
                     nodes.push(ParserNode {
                         identifier,
                         depth,
                         is_constructed: true,
                         encoded_bytes,
                         data_bytes: None,
                     });
                     
                     let mut check_sub = sub_data;
                     while !check_sub.is_empty() {
                         Self::_parse_node(&mut check_sub, rules, depth + 1, nodes)?;
                     }
                 } else {
                     nodes.push(ParserNode {
                         identifier,
                         depth,
                         is_constructed: false,
                         encoded_bytes,
                         data_bytes: Some(sub_data),
                     });
                 }
            }
            ASN1Length::Indefinite => {
                if !rules.indefinite_length_allowed() {
                    return Err(ASN1Error::new(
                        ErrorCode::UnsupportedFieldLength,
                        "Indefinite form of field length not supported in DER.".to_string(),
                        file!().to_string(),
                        line!(),
                    ));
                }
                if !constructed {
                     return Err(ASN1Error::new(
                        ErrorCode::UnsupportedFieldLength,
                        "Indefinite-length field must have constructed identifier".to_string(),
                        file!().to_string(),
                        line!(),
                    ));
                }

                nodes.push(ParserNode {
                    identifier,
                    depth,
                    is_constructed: true,
                    encoded_bytes: Bytes::new(), // placeholder
                    data_bytes: None,
                });
                let last_index = nodes.len() - 1;

                loop {
                    if data.is_empty() {
                        return Err(ASN1Error::new(
                            ErrorCode::TruncatedASN1Field,
                            "Indefinite-length field missing end-of-content marker".to_string(),
                            file!().to_string(),
                            line!(),
                        ));
                    }
                    Self::_parse_node(data, rules, depth + 1, nodes)?;
                    let found_end_marker =
                        matches!(nodes.last(), Some(node) if node.is_end_marker());
                    if found_end_marker {
                        nodes.pop();
                        break;
                    }
                }

                let consumed = original_data.len() - data.len();
                let encoded_bytes = original_data.slice(0..consumed);
                nodes[last_index].encoded_bytes = encoded_bytes;
            }
        }

        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ASN1Length {
    Indefinite,
    Definite(u64), // Using u64 to store UInt
}

fn _read_asn1_length(data: &mut Bytes, minimal_encoding: bool) -> Result<ASN1Length, ASN1Error> {
    if data.is_empty() {
        return Err(ASN1Error::new(ErrorCode::TruncatedASN1Field, "".to_string(), file!().to_string(), line!()));
    }
    let first_byte = data.split_to(1)[0];
    
    if first_byte == 0x80 {
        return Ok(ASN1Length::Indefinite);
    }
    
    if (first_byte & 0x80) == 0x80 {
        // Long form
        let field_length = (first_byte & 0x7F) as usize;
        if data.len() < field_length {
            return Err(ASN1Error::new(
                ErrorCode::TruncatedASN1Field,
                "".to_string(),
                file!().to_string(),
                line!(),
            ));
        }
        let length_bytes = data.split_to(field_length);
        let mut length: u64 = 0;
        for &b in length_bytes.iter() {
            length = length.checked_mul(256).ok_or_else(|| {
                ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "Field length exceeds supported range".to_string(),
                    file!().to_string(),
                    line!(),
                )
            })?;
            length += b as u64;
        }

        if minimal_encoding {
            if length < 128 {
                return Err(ASN1Error::new(
                    ErrorCode::UnsupportedFieldLength,
                    "Field length encoded in long form, but DER requires short form".to_string(),
                    file!().to_string(),
                    line!(),
                ));
            }
            let required_bytes = minimal_octet_len(length);
            if field_length > required_bytes {
                return Err(ASN1Error::new(
                    ErrorCode::UnsupportedFieldLength,
                    "Field length encoded in excessive number of bytes".to_string(),
                    file!().to_string(),
                    line!(),
                ));
            }
        }

        Ok(ASN1Length::Definite(length))
    } else {
        Ok(ASN1Length::Definite(first_byte as u64))
    }
}

fn read_asn1_discipline_uint(data: &mut Bytes) -> Result<(u64, usize), ASN1Error> {
    // Base 128
    let mut value: u64 = 0;
    let mut read = 0;
    loop {
        if data.is_empty() {
             return Err(ASN1Error::new(ErrorCode::TruncatedASN1Field, "".to_string(), file!().to_string(), line!()));
        }
        let byte = data.split_to(1)[0];
        read += 1;
        let chunk = u64::from(byte & 0x7F);
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(chunk))
            .ok_or_else(|| {
                ASN1Error::new(
                    ErrorCode::InvalidASN1Object,
                    "Base-128 integer exceeds u64 range".to_string(),
                    file!().to_string(),
                    line!(),
                )
            })?;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    Ok((value, read))
}


#[derive(Debug, Clone)]
pub struct ASN1NodeCollection {
    // We use Arc to share the vector of all nodes parsed in the result
    nodes: Arc<Vec<ParserNode>>,
    // range of indices in `nodes` that belong to this collection
    range: Range<usize>,
    depth: usize,
}

impl ASN1NodeCollection {
    pub(crate) fn new(nodes: Arc<Vec<ParserNode>>, range: Range<usize>, depth: usize) -> Self {
        ASN1NodeCollection { nodes, range, depth }
    }
}

impl IntoIterator for ASN1NodeCollection {
    type Item = ASN1Node;
    type IntoIter = ASN1NodeCollectionIterator;

    fn into_iter(self) -> Self::IntoIter {
        ASN1NodeCollectionIterator {
            nodes: self.nodes,
            range: self.range,
            _depth: self.depth,
        }
    }
}


pub struct ASN1NodeCollectionIterator {
    nodes: Arc<Vec<ParserNode>>,
    range: Range<usize>,
    _depth: usize,
}

impl ASN1NodeCollectionIterator {
    pub fn peek(&self) -> Option<ASN1Node> {
        if self.range.start >= self.range.end {
            return None;
        }
        let index = self.range.start;
        let end_index = self.subtree_end_index(index);
        Some(self.clone_node(index, end_index))
    }

    fn subtree_end_index(&self, index: usize) -> usize {
        let node_depth = self.nodes[index].depth;
        let mut search_index = index + 1;
        while search_index < self.range.end {
            if self.nodes[search_index].depth <= node_depth {
                break;
            }
            search_index += 1;
        }
        search_index
    }

    fn clone_node(&self, index: usize, end_index: usize) -> ASN1Node {
        let node = &self.nodes[index];
        if node.is_constructed {
            let collection = ASN1NodeCollection::new(
                self.nodes.clone(),
                (index + 1)..end_index,
                node.depth,
            );
            ASN1Node {
                identifier: node.identifier,
                content: Content::Constructed(collection),
                encoded_bytes: node.encoded_bytes.clone(),
            }
        } else {
            ASN1Node {
                identifier: node.identifier,
                content: Content::Primitive(node.data_bytes.clone().unwrap()),
                encoded_bytes: node.encoded_bytes.clone(),
            }
        }
    }
}

impl Iterator for ASN1NodeCollectionIterator {
    type Item = ASN1Node;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }
        let index = self.range.start;
        let end_index = self.subtree_end_index(index);
        self.range.start = end_index;
        Some(self.clone_node(index, end_index))
    }
}


#[derive(Debug, Clone)]
pub struct ASN1Node {
    pub identifier: ASN1Identifier,
    pub content: Content,
    pub encoded_bytes: Bytes,
}

impl ASN1Node {
    pub fn is_constructed(&self) -> bool {
        matches!(self.content, Content::Constructed(_))
    }
}

#[derive(Debug, Clone)]
pub enum Content {
    Constructed(ASN1NodeCollection),
    Primitive(Bytes),
}



#[cfg(test)]
    mod tests {
    use super::*;
    use bytes::{BytesMut};
    use std::sync::Arc;

    #[test]
    fn test_parse_empty_data() {
        let data = Bytes::from(vec![]);
        // EncodingRules::Distinguished is DER
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_truncated_tag() {
        let data = Bytes::from(vec![0x1F]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_truncated_length() {
        let data = Bytes::from(vec![0x02]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_truncated_value() {
        let data = Bytes::from(vec![0x02, 0x01]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_long_form_tag_number_too_small_rejected() {
        // Long-form tag encoding (0x1F) must not be used for tag numbers < 0x1F.
        // Here the tag number is 0x1E, which must be rejected.
        let data = Bytes::from(vec![0x1F, 0x1E, 0x00]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::InvalidASN1Object);
    }

    #[test]
    fn test_parse_long_form_tag_number_boundary_ok() {
        // Tag number 0x1F is the smallest value that is valid to encode in long form.
        let data = Bytes::from(vec![0x1F, 0x1F, 0x00]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_ok());
    }

    #[test]
    fn test_parse_long_form_tag_number_above_boundary_ok() {
        // A value above the boundary should also be accepted.
        let data = Bytes::from(vec![0x1F, 0x20, 0x00]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_ok());
    }

    #[test]
    fn test_der_rejects_non_minimal_length_encoding() {
        // DER requires minimal length encoding.
        // Length 1 encoded as 0x81 0x01 is non-minimal and must be rejected in DER.
        let data = Bytes::from(vec![0x02, 0x81, 0x01, 0x00]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::UnsupportedFieldLength);
    }

    #[test]
    fn test_ber_allows_non_minimal_length_encoding() {
        // BER (Basic) allows non-minimal length encodings.
        let data = Bytes::from(vec![0x02, 0x81, 0x01, 0x00]);
        let res = ParseResult::parse(data, EncodingRules::Basic);
        assert!(res.is_ok());
    }

    #[test]
    fn test_parse_extra_data() {
        let data = Bytes::from(vec![0x02, 0x01, 0x00, 0xFF]);
        // parse returns a list of nodes.
        // If we use ParseResult::parse directly, it checks !current_data.is_empty().
        let res = ParseResult::parse(data.clone(), EncodingRules::Distinguished);
        // It should err because of trailing unparsed data
        assert!(res.is_err());
        
    }

    #[test]
    fn test_huge_length() {
        let data = Bytes::from(vec![0x02, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]);
        let res = ParseResult::parse(data, EncodingRules::Distinguished);
        assert!(res.is_err());
    }

    #[test]
    fn test_recursion_limit() {
        let data = vec![0x30, 0x02, 0x30, 0x00];
        // der::parse requires generic T: DERParseable.
        // Actually, just checking ParseResult::parse which is what is tested here.
        let res = ParseResult::parse(Bytes::from(data), EncodingRules::Distinguished);
        assert!(res.is_ok());
    }

    #[test]
    fn test_recursion_limit_boundary_ok() {
        // MAXIMUM_NODE_DEPTH is 50, and the parser checks the depth at the start of each
        // _parse_node call.
        //
        // With BER indefinite length nesting, the deepest call is typically the innermost
        // end-of-content (EOC) marker, which is one level deeper than the innermost
        // constructed node.
        //
        // 49 nested sequences => deepest EOC is at depth 50, which should be allowed.
        let mut data = Vec::new();
        for _ in 0..49 {
            data.push(0x30);
            data.push(0x80);
        }
        for _ in 0..49 {
            data.push(0x00);
            data.push(0x00);
        }

        let res = ParseResult::parse(Bytes::from(data), EncodingRules::Basic);
        assert!(res.is_ok());
    }

    #[test]
    fn test_recursion_limit_boundary_err() {
        // 50 nested sequences => deepest EOC is at depth 51, which should exceed the limit.
        let mut data = Vec::new();
        for _ in 0..50 {
            data.push(0x30);
            data.push(0x80);
        }
        for _ in 0..50 {
            data.push(0x00);
            data.push(0x00);
        }

        let res = ParseResult::parse(Bytes::from(data), EncodingRules::Basic);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::InvalidASN1Object);
    }

    #[test]
    fn test_deep_recursion_error() {
        // limit is 50.
        // Construct 52 nested sequences.
        // Each sequence: 0x30 0xXX ...
        // To be valid, they must have length. Indefinite length not allowed in DER, but allowed in Basic.
        // Let's use BER (Basic) with indefinite length for easier construction?
        // Or just definite length with enough bytes. 
        // 0x30 0x80 ... (indefinite) 51 times. Then 0x00 0x00 51 times.
        
        let mut data = Vec::new();
        for _ in 0..52 {
            data.push(0x30);
            data.push(0x80); // Indefinite
        }
        for _ in 0..52 {
            data.push(0x00);
            data.push(0x00);
        }
        
        let res = ParseResult::parse(Bytes::from(data), EncodingRules::Basic);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::InvalidASN1Object);
        // "Excessive stack depth"
    }

    #[test]
    fn test_is_end_marker() {
        let node = ParserNode {
            identifier: ASN1Identifier::new(0, TagClass::Universal),
            depth: 0,
            is_constructed: false,
            encoded_bytes: Bytes::from(vec![0x00, 0x00]),
            data_bytes: Some(Bytes::from(vec![])),
        };
        assert!(node.is_end_marker());
        
        // Negative cases
        let node2 = ParserNode {
            identifier: ASN1Identifier::new(1, TagClass::Universal), // Not 0
            depth: 0,
            is_constructed: false,
            encoded_bytes: Bytes::from(vec![0x00, 0x00]),
            data_bytes: Some(Bytes::from(vec![])),
        };
        assert!(!node2.is_end_marker());
        
        let node3 = ParserNode {
            identifier: ASN1Identifier::new(0, TagClass::Universal),
            depth: 0,
            is_constructed: false,
            encoded_bytes: Bytes::from(vec![0x00]), // Length != 2
            data_bytes: Some(Bytes::from(vec![])),
        };
        assert!(!node3.is_end_marker());
    }

    #[test]
    fn test_indefinite_constructed_encoded_bytes_matches_input() {
        // Verify that encoded_bytes for an indefinite-length constructed node covers the entire
        // encoding up to (and including) the end-of-content marker.
        let data = vec![
            0x30, 0x80, // SEQUENCE, indefinite length
            0x02, 0x01, 0x00, // INTEGER (0)
            0x00, 0x00, // EOC
        ];

        let res = ParseResult::parse(Bytes::from(data.clone()), EncodingRules::Basic).unwrap();
        assert!(!res.nodes.is_empty());
        assert!(res.nodes[0].is_constructed);
        assert_eq!(res.nodes[0].encoded_bytes.as_ref(), data.as_slice());
    }

    #[test]
    fn test_der_rejects_indefinite_length_encoding() {
        let data = vec![
            0x30, 0x80, // SEQUENCE, indefinite length
            0x00, 0x00, // EOC
        ];

        let err = ParseResult::parse(Bytes::from(data), EncodingRules::Distinguished).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedFieldLength);
    }

    #[test]
    fn test_indefinite_length_missing_end_marker_rejected() {
        let data = vec![
            0x30, 0x80, // SEQUENCE, indefinite length
            0x02, 0x01, 0x00, // INTEGER
                              // Missing end-of-content marker
        ];

        let err = ParseResult::parse(Bytes::from(data), EncodingRules::Basic).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TruncatedASN1Field);
    }

    #[test]
    fn test_read_asn1_length_long_form_with_exact_bytes() {
        let mut data = Bytes::from(vec![0x82, 0x01, 0x02]);
        let result = super::_read_asn1_length(&mut data, false).unwrap();
        match result {
            super::ASN1Length::Definite(value) => assert_eq!(value, 0x0102),
            super::ASN1Length::Indefinite => panic!("expected definite length"),
        }
        assert!(data.is_empty());
    }

    #[test]
    fn test_read_asn1_length_rejects_excessive_length_bytes() {
        let mut data = Bytes::from(vec![0x83, 0x00, 0x01, 0x02]);
        let err = super::_read_asn1_length(&mut data, true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedFieldLength);
    }

    #[test]
    fn test_read_asn1_length_rejects_overlong_encoding() {
        let mut data = Bytes::from(vec![0x83, 0x00, 0x00, 0x80]); // 128 encoded using 3 bytes
        let err = super::_read_asn1_length(&mut data, true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedFieldLength);
    }

    #[test]
    fn test_der_allows_long_form_for_length_128() {
        let mut payload = BytesMut::from(&[0x04, 0x81, 0x80][..]);
        payload.extend_from_slice(&vec![0u8; 128]);
        assert!(ParseResult::parse(payload.freeze(), EncodingRules::Distinguished).is_ok());
    }

    #[test]
    fn test_read_asn1_discipline_uint_multi_byte() {
        let mut data = Bytes::from(vec![0x81, 0x01]);
        let (value, read) = super::read_asn1_discipline_uint(&mut data).unwrap();
        assert_eq!(value, 129);
        assert_eq!(read, 2);
        assert!(data.is_empty());
    }

    #[test]
    fn test_read_asn1_discipline_uint_truncated_errors() {
        let mut data = Bytes::from(vec![0x80]);
        let err = super::read_asn1_discipline_uint(&mut data).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TruncatedASN1Field);
    }

    #[test]
    fn test_read_asn1_discipline_uint_overflow_errors() {
        let mut bytes = vec![0xFF; 10];
        bytes.push(0x7F);
        let mut data = Bytes::from(bytes);
        let err = super::read_asn1_discipline_uint(&mut data).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidASN1Object);
    }

    #[test]
    fn test_minimal_octet_len_values() {
        assert_eq!(super::minimal_octet_len(0), 1);
        assert_eq!(super::minimal_octet_len(1), 1);
        assert_eq!(super::minimal_octet_len(0x80), 1);
        assert_eq!(super::minimal_octet_len(u64::MAX), 8);
    }

    fn encode_base128(mut value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0];
        }
        let mut stack = Vec::new();
        while value > 0 {
            stack.push((value & 0x7F) as u8);
            value >>= 7;
        }
        let mut out = Vec::with_capacity(stack.len());
        for idx in (0..stack.len()).rev() {
            let mut byte = stack[idx];
            if idx != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    #[test]
    fn test_read_asn1_discipline_uint_accepts_max_value() {
        let encoded = encode_base128(u64::MAX);
        let mut data = Bytes::from(encoded.clone());
        let (decoded, consumed) = super::read_asn1_discipline_uint(&mut data).unwrap();
        assert_eq!(decoded, u64::MAX);
        assert_eq!(consumed, encoded.len());
        assert!(data.is_empty());
    }

    #[test]
    fn test_node_collection_iterator_yields_children_in_order() {
        fn bytes(data: &[u8]) -> Bytes {
            Bytes::from(data.to_vec())
        }

        let nodes = Arc::new(vec![
            ParserNode {
                identifier: ASN1Identifier::SEQUENCE,
                depth: 1,
                is_constructed: true,
                encoded_bytes: bytes(&[0x30, 0x06]),
                data_bytes: None,
            },
            ParserNode {
                identifier: ASN1Identifier::INTEGER,
                depth: 2,
                is_constructed: false,
                encoded_bytes: bytes(&[0x02, 0x01, 0x01]),
                data_bytes: Some(bytes(&[0x01])),
            },
            ParserNode {
                identifier: ASN1Identifier::SEQUENCE,
                depth: 2,
                is_constructed: true,
                encoded_bytes: bytes(&[0x30, 0x03]),
                data_bytes: None,
            },
            ParserNode {
                identifier: ASN1Identifier::INTEGER,
                depth: 3,
                is_constructed: false,
                encoded_bytes: bytes(&[0x02, 0x01, 0x02]),
                data_bytes: Some(bytes(&[0x02])),
            },
        ]);

        let collection = ASN1NodeCollection::new(nodes.clone(), 1..nodes.len(), 1);
        let mut iter = collection.into_iter();

        let first = iter.next().expect("first child");
        match first.content {
            Content::Primitive(bytes) => assert_eq!(bytes.as_ref(), &[0x01]),
            Content::Constructed(_) => panic!("expected primitive child"),
        }

        let second = iter.next().expect("second child");
        match second.content {
            Content::Constructed(child_collection) => {
                let mut child_iter = child_collection.into_iter();
                let grandchild = child_iter.next().expect("grandchild");
                match grandchild.content {
                    Content::Primitive(bytes) => assert_eq!(bytes.as_ref(), &[0x02]),
                    Content::Constructed(_) => panic!("expected primitive grandchild"),
                }
                assert!(child_iter.next().is_none());
            }
            Content::Primitive(_) => panic!("expected constructed child"),
        }

        assert!(iter.next().is_none());
    }
}

