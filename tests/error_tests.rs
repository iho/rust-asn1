use rust_asn1::errors::{ASN1Error, ErrorCode};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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
    
    for (i, code) in codes.iter().enumerate() {
        let reason = format!("Reason-{i}");
        let file = format!("file{i}.rs");
        let line = 100 + i as u32;
        let err = ASN1Error::new(*code, reason.clone(), file.clone(), line);
        let display = format!("{}", err);
        assert!(display.contains("ASN1Error"));
        assert!(display.contains(&reason));
        assert!(display.contains(&format!("{file}:{line}")));

        let debug = format!("{:?}", err);
        assert!(debug.contains("ASN1Error"));

        // Assert equality and hashing
        let err2 = err.clone();
        assert_eq!(err, err2);

        let mut set = std::collections::HashSet::new();
        assert!(set.insert(err.clone()));
        assert!(!set.insert(err.clone()));
        assert_eq!(set.len(), 1);

        // Variations should compare unequal
        assert_ne!(
            err,
            ASN1Error::new(
                *code,
                format!("{reason}-diff"),
                file.clone(),
                line
            )
        );
        assert_ne!(
            err,
            ASN1Error::new(*code, reason.clone(), format!("{file}.other"), line)
        );
        assert_ne!(
            err,
            ASN1Error::new(*code, reason.clone(), file.clone(), line + 1)
        );
        assert_ne!(
            err,
            ASN1Error::new(
                if *code == ErrorCode::InvalidASN1Object {
                    ErrorCode::UnexpectedFieldType
                } else {
                    ErrorCode::InvalidASN1Object
                },
                reason.clone(),
                file.clone(),
                line
            )
        );

        let diff_hash = ASN1Error::new(*code, format!("{reason}-hash"), file.clone(), line);
        assert!(set.insert(diff_hash.clone()));
        assert_eq!(set.len(), 2);

        // Hashes should differ when any field differs
        let base_hash = hash_value(&err);
        assert_ne!(base_hash, hash_value(&diff_hash));
        assert_ne!(
            base_hash,
            hash_value(&ASN1Error::new(*code, reason.clone(), file.clone(), line + 1))
        );
        assert_ne!(
            base_hash,
            hash_value(&ASN1Error::new(
                if *code == ErrorCode::UnexpectedFieldType {
                    ErrorCode::InvalidASN1Object
                } else {
                    ErrorCode::UnexpectedFieldType
                },
                reason.clone(),
                file.clone(),
                line
            ))
        );
    }
}

fn hash_value(err: &ASN1Error) -> u64 {
    let mut hasher = DefaultHasher::new();
    err.hash(&mut hasher);
    hasher.finish()
}
