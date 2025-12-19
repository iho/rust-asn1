use std::fmt;

#[derive(Debug, Clone)]
pub struct ASN1Error {
    backing: Backing,
}

#[derive(Debug, Clone)]
struct Backing {
    code: ErrorCode,
    reason: String,
    file: String,
    line: u32,
}

impl ASN1Error {
    pub fn new(code: ErrorCode, reason: String, file: String, line: u32) -> Self {
        ASN1Error {
            backing: Backing {
                code,
                reason,
                file,
                line,
            },
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.backing.code
    }
}

impl PartialEq for ASN1Error {
    fn eq(&self, other: &Self) -> bool {
        self.backing.code == other.backing.code
    }
}

impl Eq for ASN1Error {}

impl std::hash::Hash for ASN1Error {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.backing.code.hash(state);
    }
}

impl fmt::Display for ASN1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ASN1Error.{:?}: {} {}:{}",
            self.backing.code, self.backing.reason, self.backing.file, self.backing.line
        )
    }
}

impl std::error::Error for ASN1Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    UnexpectedFieldType,
    InvalidASN1Object,
    InvalidASN1IntegerEncoding,
    TruncatedASN1Field,
    UnsupportedFieldLength,
    InvalidPEMDocument,
    InvalidStringRepresentation,
    TooFewOIDComponents,
}
