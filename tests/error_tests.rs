use rust_asn1::errors::{ASN1Error, ErrorCode};

#[test]
fn test_error_display() {
    let codes = vec![
        ErrorCode::UnexpectedFieldType,
        ErrorCode::InvalidASN1Object,
        ErrorCode::InvalidASN1IntegerEncoding,
        ErrorCode::TruncatedASN1Field,
        ErrorCode::UnsupportedFieldLength,
        ErrorCode::InvalidPEMDocument,
        ErrorCode::InvalidStringRepresentation,
        ErrorCode::TooFewOIDComponents,
    ];
    
    for code in codes {
        let err = ASN1Error::new(code, "Reason".to_string(), "file.rs".to_string(), 123);
        let display = format!("{}", err);
        assert!(display.contains("ASN1Error"));
        assert!(display.contains("Reason"));
        assert!(display.contains("file.rs:123"));
        
        let debug = format!("{:?}", err);
        assert!(debug.contains("ASN1Error"));
        
        // Assert equality and hashing (derived)
        let err2 = err.clone();
        assert_eq!(err, err2);
        
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(err);
    }
}
