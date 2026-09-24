use holonomy_core::ingestion::s3_client::{Predicate, PredicateValue};
use parquet::file::statistics::Statistics;

#[test]
fn test_predicate_logic_int64() {
    let stats_int = Statistics::int64(Some(10), Some(20), None, Some(0), false);

    // Eq
    let p_eq_in = Predicate::Eq {
        column: "c".into(),
        value: PredicateValue::Int64(15),
    };
    assert!(
        p_eq_in.evaluate_statistics(&stats_int),
        "Eq 15 should be true for [10, 20]"
    );

    let p_eq_out_high = Predicate::Eq {
        column: "c".into(),
        value: PredicateValue::Int64(25),
    };
    assert!(
        !p_eq_out_high.evaluate_statistics(&stats_int),
        "Eq 25 should be false for [10, 20]"
    );

    let p_eq_out_low = Predicate::Eq {
        column: "c".into(),
        value: PredicateValue::Int64(5),
    };
    assert!(
        !p_eq_out_low.evaluate_statistics(&stats_int),
        "Eq 5 should be false for [10, 20]"
    );

    // Gt
    let p_gt_in = Predicate::Gt {
        column: "c".into(),
        value: PredicateValue::Int64(15),
    };
    assert!(
        p_gt_in.evaluate_statistics(&stats_int),
        "Gt 15 should be true for max=20"
    );

    let p_gt_out = Predicate::Gt {
        column: "c".into(),
        value: PredicateValue::Int64(25),
    };
    assert!(
        !p_gt_out.evaluate_statistics(&stats_int),
        "Gt 25 should be false for max=20"
    );

    // Lt
    let p_lt_in = Predicate::Lt {
        column: "c".into(),
        value: PredicateValue::Int64(15),
    };
    assert!(
        p_lt_in.evaluate_statistics(&stats_int),
        "Lt 15 should be true for min=10"
    );

    let p_lt_out = Predicate::Lt {
        column: "c".into(),
        value: PredicateValue::Int64(5),
    };
    assert!(
        !p_lt_out.evaluate_statistics(&stats_int),
        "Lt 5 should be false for min=10"
    );
}

#[test]
fn test_predicate_logic_int32() {
    let stats_int = Statistics::int32(Some(10), Some(20), None, Some(0), false);

    // Eq
    let p_eq_in = Predicate::Eq {
        column: "c".into(),
        value: PredicateValue::Int64(15),
    };
    assert!(
        p_eq_in.evaluate_statistics(&stats_int),
        "Eq 15 should be true for [10, 20]"
    );

    let p_eq_out_high = Predicate::Eq {
        column: "c".into(),
        value: PredicateValue::Int64(25),
    };
    assert!(
        !p_eq_out_high.evaluate_statistics(&stats_int),
        "Eq 25 should be false for [10, 20]"
    );

    // Gt
    let p_gt_in = Predicate::Gt {
        column: "c".into(),
        value: PredicateValue::Int64(15),
    };
    assert!(
        p_gt_in.evaluate_statistics(&stats_int),
        "Gt 15 should be true for max=20"
    );

    let p_gt_out = Predicate::Gt {
        column: "c".into(),
        value: PredicateValue::Int64(25),
    };
    assert!(
        !p_gt_out.evaluate_statistics(&stats_int),
        "Gt 25 should be false for max=20"
    );
}
