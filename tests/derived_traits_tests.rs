use rust_asn1::asn1_types::*;
use rust_asn1::asn1::{EncodingRules, Content};
use rust_asn1::errors::{ASN1Error, ErrorCode};
use bytes::Bytes;
use chrono::Utc;

#[test]
fn test_derived_traits() {
    // ASN1Boolean
    let b = ASN1Boolean(true);
    let b2 = b.clone();
    assert_eq!(b, b2);
    assert_eq!(format!("{:?}", b), "ASN1Boolean(true)");
    assert!(check_hash(&b));

    // ASN1Integer
    let i = ASN1Integer::from(42);
    let i2 = i.clone();
    assert_eq!(i, i2);
    assert!(format!("{:?}", i).contains("ASN1Integer"));
    assert!(check_hash(&i));

    // ASN1OctetString
    let o = ASN1OctetString(Bytes::from(vec![1, 2, 3]));
    let o2 = o.clone();
    assert_eq!(o, o2);
    assert!(format!("{:?}", o).contains("ASN1OctetString"));
    assert!(check_hash(&o));

    // ASN1Identifier
    let id = ASN1Identifier::INTEGER;
    let id2 = id.clone();
    assert_eq!(id, id2);
    assert!(format!("{:?}", id).contains("ASN1Identifier"));
    assert!(check_hash(&id));
    
    // TagClass
    let tc = TagClass::Universal;
    let tc2 = tc.clone();
    assert_eq!(tc, tc2);
    assert!(format!("{:?}", tc).contains("Universal"));
    assert!(check_hash(&tc));

    // EncodingRules
    let er = EncodingRules::Distinguished;
    let er2 = er.clone();
    assert_eq!(er, er2);
    assert!(format!("{:?}", er).contains("Distinguished"));
    // Eq is derived

    // ErrorCode
    let ec = ErrorCode::InvalidASN1Object;
    let ec2 = ec.clone();
    assert_eq!(ec, ec2);
    assert!(format!("{:?}", ec).contains("InvalidASN1Object"));
    assert!(check_hash(&ec));
    
    // Content
    let c = Content::Primitive(Bytes::from(vec![1]));
    assert!(format!("{:?}", c).contains("Primitive"));

    // ASN1Boolean From/Into
    let b_from: ASN1Boolean = true.into();
    let bool_val: bool = b_from.into();
    assert!(bool_val);
    
    // ASN1Integer From/Into
    let i_from: ASN1Integer = 123i64.into();
    let i_u8: ASN1Integer = (123u8 as i64).into();
    // Test clone/debug for all these is covered by generic derive logic usually but let's be sure
    assert_eq!(i_from, ASN1Integer::from(123));

    // ASN1BitString
    let bs = ASN1BitString { bytes: Bytes::from(vec![0xFF]), padding_bits: 0 };
    let bs2 = bs.clone();
    assert_eq!(bs, bs2);
    assert!(format!("{:?}", bs).contains("ASN1BitString"));
    assert!(check_hash(&bs));
    
    // ASN1Null
    let n = ASN1Null;
    let n2 = n.clone();
    assert_eq!(n, n2);
    assert!(format!("{:?}", n).contains("ASN1Null"));
    assert!(check_hash(&n));
    
    // ASN1ObjectIdentifier
    let oid = ASN1ObjectIdentifier::new(&[1, 2, 840]).unwrap();
    let oid2 = oid.clone();
    assert_eq!(oid, oid2);
    assert!(format!("{:?}", oid).contains("ASN1ObjectIdentifier"));
    assert!(check_hash(&oid));
    
    // GeneralizedTime
    let now = Utc::now();
    let gt = GeneralizedTime(now);
    let gt2 = gt.clone();
    assert_eq!(gt, gt2);
    assert!(format!("{:?}", gt).contains("GeneralizedTime"));
    assert!(check_hash(&gt));
    let gt_from: GeneralizedTime = now.into();
    assert_eq!(gt, gt_from);
    
    // UTCTime
    let ut = UTCTime(now);
    let ut2 = ut.clone();
    assert_eq!(ut, ut2);
    assert!(format!("{:?}", ut).contains("UTCTime"));
    assert!(check_hash(&ut));
    let ut_from: UTCTime = now.into();
    assert_eq!(ut, ut_from);
    
    // Strings
    let s = ASN1UTF8String::new("A".to_string()).unwrap();
    let s2 = s.clone();
    assert_eq!(s, s2);
    assert!(check_hash(&s));
    let s_str: String = s.into();
    assert_eq!(s_str, "A");
    
    let ps = ASN1PrintableString::new("A".to_string()).unwrap();
    let ps2 = ps.clone();
    assert_eq!(ps, ps2);
    
    let ia5 = ASN1IA5String::new("A".to_string()).unwrap();
    let ia5_2 = ia5.clone();
    assert_eq!(ia5, ia5_2);
    
    let num = ASN1NumericString::new("123".to_string()).unwrap();
    let num2 = num.clone();
    assert_eq!(num, num2);
}

fn check_hash<T: std::hash::Hash>(t: &T) -> bool {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut hasher = DefaultHasher::new();
    t.hash(&mut hasher);
    hasher.finish() != 0
}

#[test]
fn test_encoding_rules_methods() {
    let ber = EncodingRules::Basic;
    let der = EncodingRules::Distinguished;

    assert!(ber.indefinite_length_allowed());
    assert!(!der.indefinite_length_allowed());

    assert!(ber.non_minimal_encoded_lengths_allowed());
    assert!(!der.non_minimal_encoded_lengths_allowed());
}
