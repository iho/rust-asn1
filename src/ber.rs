use crate::asn1::{ASN1Node, ASN1NodeCollection, ASN1NodeCollectionIterator, ParseResult, EncodingRules};
use crate::asn1_types::ASN1Identifier;
use crate::errors::{ASN1Error, ErrorCode};
use crate::der::{DERParseable, DERSerializable, DERImplicitlyTaggable};
use bytes::Bytes;

pub trait BERParseable: DERParseable {
    fn from_ber_node(node: ASN1Node) -> Result<Self, ASN1Error> {
        Self::from_der_node(node)
    }
    
    fn from_ber_iterator(iter: &mut ASN1NodeCollectionIterator) -> Result<Self, ASN1Error> {
         let node = iter.next().ok_or_else(|| ASN1Error::new(
            ErrorCode::InvalidASN1Object,
            format!("Unable to decode {}, no ASN.1 nodes to decode", std::any::type_name::<Self>()),
            file!().to_string(),
            line!(),
        ))?;
        Self::from_ber_node(node)
    }
}

pub trait BERSerializable: DERSerializable {}

pub trait BERImplicitlyTaggable: BERParseable + BERSerializable + DERImplicitlyTaggable {
    fn from_ber_node_with_identifier(node: ASN1Node, identifier: ASN1Identifier) -> Result<Self, ASN1Error> {
        Self::from_der_node_with_identifier(node, identifier)
    }
}

pub fn parse(data: &[u8]) -> Result<ASN1Node, ASN1Error> {
    let bytes = Bytes::copy_from_slice(data);
    let result = ParseResult::parse(bytes, EncodingRules::Basic)?;
    
    let nodes = result.nodes;
    let first_node = nodes[0].clone();
    
    if first_node.is_constructed {
          let nodes_arc = std::sync::Arc::new(nodes);
          let range = 1..nodes_arc.len();
          let collection = ASN1NodeCollection::new(nodes_arc, range, first_node.depth);
          Ok(ASN1Node {
              identifier: first_node.identifier,
              content: crate::asn1::Content::Constructed(collection),
              encoded_bytes: first_node.encoded_bytes,
          })
     } else {
          Ok(ASN1Node {
              identifier: first_node.identifier,
              content: crate::asn1::Content::Primitive(first_node.data_bytes.unwrap()),
              encoded_bytes: first_node.encoded_bytes,
          })
     }
}

pub fn sequence<T, F>(node: ASN1Node, identifier: ASN1Identifier, builder: F) -> Result<T, ASN1Error>
where
    F: FnOnce(&mut ASN1NodeCollectionIterator) -> Result<T, ASN1Error>,
{
    crate::der::sequence(node, identifier, builder)
}
