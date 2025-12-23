use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ASN1Identifier {
    pub tag_number: u64,
    pub tag_class: TagClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl TagClass {
    pub(crate) fn from_top_byte(top_byte: u8) -> Self {
        [
            TagClass::Universal,
            TagClass::Application,
            TagClass::ContextSpecific,
            TagClass::Private,
        ][(top_byte >> 6) as usize]
    }

    pub(crate) fn top_byte_flags(&self) -> u8 {
        match self {
            TagClass::Universal => 0x00,
            TagClass::Application => 0x01 << 6,
            TagClass::ContextSpecific => 0x02 << 6,
            TagClass::Private => 0x03 << 6,
        }
    }
}

impl ASN1Identifier {
    pub const fn new(tag_number: u64, tag_class: TagClass) -> Self {
        ASN1Identifier {
            tag_number,
            tag_class,
        }
    }

    pub(crate) fn from_short_identifier(short_identifier: u8) -> Self {
        assert!(short_identifier & 0x1F != 0x1F);
        ASN1Identifier {
            tag_class: TagClass::from_top_byte(short_identifier),
            tag_number: (short_identifier & 0x1F) as u64,
        }
    }

    pub(crate) fn short_form(&self) -> Option<u8> {
        if self.tag_number < 0x1f {
            let mut base_number = self.tag_number as u8;
            base_number |= self.tag_class.top_byte_flags();
            Some(base_number)
        } else {
            None
        }
    }

    // Static constants
    pub const OBJECT_IDENTIFIER: ASN1Identifier = ASN1Identifier::new(0x06, TagClass::Universal);
    pub const BIT_STRING: ASN1Identifier = ASN1Identifier::new(0x03, TagClass::Universal);
    pub const OCTET_STRING: ASN1Identifier = ASN1Identifier::new(0x04, TagClass::Universal);
    pub const INTEGER: ASN1Identifier = ASN1Identifier::new(0x02, TagClass::Universal);
    pub const REAL: ASN1Identifier = ASN1Identifier::new(0x09, TagClass::Universal);
    pub const SEQUENCE: ASN1Identifier = ASN1Identifier::new(0x10, TagClass::Universal);
    pub const SET: ASN1Identifier = ASN1Identifier::new(0x11, TagClass::Universal);
    pub const NULL: ASN1Identifier = ASN1Identifier::new(0x05, TagClass::Universal);
    pub const BOOLEAN: ASN1Identifier = ASN1Identifier::new(0x01, TagClass::Universal);
    pub const ENUMERATED: ASN1Identifier = ASN1Identifier::new(0x0a, TagClass::Universal);
    pub const UTF8_STRING: ASN1Identifier = ASN1Identifier::new(0x0c, TagClass::Universal);
    pub const NUMERIC_STRING: ASN1Identifier = ASN1Identifier::new(0x12, TagClass::Universal);
    pub const PRINTABLE_STRING: ASN1Identifier = ASN1Identifier::new(0x13, TagClass::Universal);
    pub const TELETEX_STRING: ASN1Identifier = ASN1Identifier::new(0x14, TagClass::Universal);
    pub const VIDEOTEX_STRING: ASN1Identifier = ASN1Identifier::new(0x15, TagClass::Universal);
    pub const IA5_STRING: ASN1Identifier = ASN1Identifier::new(0x16, TagClass::Universal);
    pub const GRAPHIC_STRING: ASN1Identifier = ASN1Identifier::new(0x19, TagClass::Universal);
    pub const VISIBLE_STRING: ASN1Identifier = ASN1Identifier::new(0x1a, TagClass::Universal);
    pub const GENERAL_STRING: ASN1Identifier = ASN1Identifier::new(0x1b, TagClass::Universal);
    pub const UNIVERSAL_STRING: ASN1Identifier = ASN1Identifier::new(0x1c, TagClass::Universal);
    pub const BMP_STRING: ASN1Identifier = ASN1Identifier::new(0x1e, TagClass::Universal);
    pub const GENERALIZED_TIME: ASN1Identifier = ASN1Identifier::new(0x18, TagClass::Universal);
    pub const UTC_TIME: ASN1Identifier = ASN1Identifier::new(0x17, TagClass::Universal);
}

impl fmt::Display for ASN1Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class_str = match self.tag_class {
            TagClass::Universal => "Universal",
            TagClass::Application => "Application",
            TagClass::ContextSpecific => "ContextSpecific",
            TagClass::Private => "Private",
        };

        if let Some(short) = self.short_form() {
            write!(
                f,
                "ASN1Identifier(tagNumber: {}, tagClass: {}, shortForm: 0x{:02X})",
                self.tag_number, class_str, short
            )
        } else {
            write!(
                f,
                "ASN1Identifier(tagNumber: {}, tagClass: {}, longForm)",
                self.tag_number, class_str
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_class_from_top_byte() {
        assert_eq!(TagClass::from_top_byte(0x00), TagClass::Universal);
        assert_eq!(TagClass::from_top_byte(0x40), TagClass::Application);
        assert_eq!(TagClass::from_top_byte(0x80), TagClass::ContextSpecific);
        assert_eq!(TagClass::from_top_byte(0xC0), TagClass::Private);
    }

    #[test]
    fn test_tag_class_top_byte_flags() {
        assert_eq!(TagClass::Universal.top_byte_flags(), 0x00);
        assert_eq!(TagClass::Application.top_byte_flags(), 0x40);
        assert_eq!(TagClass::ContextSpecific.top_byte_flags(), 0x80);
        assert_eq!(TagClass::Private.top_byte_flags(), 0xC0);
    }

    #[test]
    fn test_identifier_display_includes_fields() {
        let id = ASN1Identifier::new(42, TagClass::ContextSpecific);
        let text = format!("{}", id);
        assert!(
            text.contains("tagNumber: 42"),
            "display text missing tag number: {}",
            text
        );
        assert!(
            text.contains("ContextSpecific"),
            "display text missing tag class: {}",
            text
        );
    }
}
