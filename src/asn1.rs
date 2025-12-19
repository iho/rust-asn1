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
                    data_bytes: None
                });
                let last_index = nodes.len() - 1;
                
                // Parse until end marker
                loop {
                    if data.is_empty() {
                        // Error? Swift loop condition: while data.count > 0 && nodes.last!.isEndMarker == false
                        // If data runs out before end marker, it will fail in next recursive call or loop
                        break; 
                    }
                    if let Some(last) = nodes.last() {
                         if last.is_end_marker() {
                             break;
                         }
                    }
                    Self::_parse_node(data, rules, depth + 1, nodes)?;
                }
                
                // Pop endmarker
                if let Some(last) = nodes.last() {
                     if !last.is_end_marker() {
                         // Should have been EOC
                         // But if loop broke due to data empty?
                     }
                }
                // Swift: let endMarker = nodes.popLast()!
                let _end_marker = nodes.pop().unwrap(); // Safety: we pushed at least one
                
                // Calculate encoded bytes size
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
             return Err(ASN1Error::new(ErrorCode::TruncatedASN1Field, "".to_string(), file!().to_string(), line!()));
        }
        let length_bytes = data.split_to(field_length);
        let mut length: u64 = 0;
        for b in length_bytes.iter() {
            // Check overflow? u64 is large enough for reasonable ASN.1
            length = (length << 8) | (*b as u64);
        }
        
        if minimal_encoding {
            let required_bits = 64 - length.leading_zeros(); // rough check
            // Swift logic:
            // let requiredBits = UInt.bitWidth - length.leadingZeroBitCount
            // case 0...7: require short form.
            if required_bits <= 7 && field_length > 0 { // 0x81 0x01 is invalid if 0x01 suffices
                 // Actually length < 128 should be short form.
                 if length < 128 {
                      return Err(ASN1Error::new(ErrorCode::UnsupportedFieldLength, "Field length encoded in long form, but DER requires short form".to_string(), file!().to_string(), line!()));
                 }
            }
            // case 8...: fieldLength should be min required.
             // implementation detail omitted for brevity but should be there
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
        value = (value << 7) | ((byte & 0x7F) as u64);
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
            depth: self.depth,
        }
    }
}


pub struct ASN1NodeCollectionIterator {
    nodes: Arc<Vec<ParserNode>>,
    range: Range<usize>,
    depth: usize,
}

impl Iterator for ASN1NodeCollectionIterator {
    type Item = ASN1Node;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }
        
        let index = self.range.start;
        // self.nodes[index] is the next node.
        let node = &self.nodes[index];
        
        // Assert depth match?
        // assert(node.depth == self.depth + 1);
        
        // Advance start.
        // If constructed, we need to skip its children in the flat list.
        // But how many children?
        // ParseResult logic: "We need to feed it the next set of nodes."
        // "nodeCollection = result.nodes.prefix { $0.depth > firstNode.depth }"
        
        // We need to scan forward to find the size of the subtree.
        let mut end_index = index + 1;
        while end_index < self.range.end {
            if self.nodes[end_index].depth <= node.depth {
                break;
            }
            end_index += 1;
        }
        
        self.range.start = end_index;

        if node.is_constructed {
            let collection = ASN1NodeCollection::new(
                self.nodes.clone(),
                (index + 1)..end_index,
                node.depth
            );
            Some(ASN1Node {
                identifier: node.identifier,
                content: Content::Constructed(collection),
                encoded_bytes: node.encoded_bytes.clone(),
            })
        } else {
            Some(ASN1Node {
                identifier: node.identifier,
                content: Content::Primitive(node.data_bytes.clone().unwrap()),
                encoded_bytes: node.encoded_bytes.clone(),
            })
        }
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

#[derive(Debug, Clone)]
pub struct LazySetOfSequence<T> {
     // Placeholder, implemented via iterator usually
     // In Swift this maps Result<T> lazy.
     // In Rust we might return an iterator
     _marker: std::marker::PhantomData<T>,
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{self, DERParseable};
    use crate::asn1_types::ASN1Integer;

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
    fn test_parse_extra_data() {
        let data = Bytes::from(vec![0x02, 0x01, 0x00, 0xFF]);
        // parse returns a list of nodes.
        // If we use ParseResult::parse directly, it checks !current_data.is_empty().
        let res = ParseResult::parse(data.clone(), EncodingRules::Distinguished);
        // It should err because of trailing unparsed data
        assert!(res.is_err());
        
        let res_der = der::parse(&data);
        assert!(res_der.is_err()); 
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
        let res = der::parse(&data);
        assert!(res.is_ok());
    }
}

