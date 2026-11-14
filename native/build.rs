#[path = "src/release_identity.rs"]
mod release_identity;

fn main() {
    println!("cargo:rerun-if-env-changed=SKYLICENSE_CERT_SHA256");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_CERT_SHA256_NEXT");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_MANIFEST_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_MIN_SECURITY_EPOCH");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_SECURITY_EPOCH");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_BUILD_ID");
    println!("cargo:rerun-if-env-changed=SKYLICENSE_ARTIFACT_CHANNEL");
    println!("cargo:rerun-if-changed=src/release_identity.rs");

    let strict = std::env::var_os("CARGO_FEATURE_SECURITY_STRICT").is_some();
    let balanced = std::env::var_os("CARGO_FEATURE_SECURITY_BALANCED").is_some();
    if strict || balanced {
        require_hex_32("SKYLICENSE_MANIFEST_PUBLIC_KEY", true);
        require_hex_32("SKYLICENSE_BUILD_ID", true);
        let minimum = require_positive_epoch("SKYLICENSE_MIN_SECURITY_EPOCH");
        let current = require_positive_epoch("SKYLICENSE_SECURITY_EPOCH");
        assert!(
            current >= minimum,
            "SKYLICENSE_SECURITY_EPOCH must be greater than or equal to SKYLICENSE_MIN_SECURITY_EPOCH"
        );
        validate_release_identity();
    }
    if strict {
        require_hex_32("SKYLICENSE_CERT_SHA256", true);
    }
    validate_optional_next_certificate_pin();
}

fn validate_release_identity() {
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }

    let channel =
        std::env::var("SKYLICENSE_ARTIFACT_CHANNEL").unwrap_or_else(|_| "production".to_string());
    let build_id = std::env::var("SKYLICENSE_BUILD_ID")
        .unwrap_or_else(|_| panic!("SKYLICENSE_BUILD_ID is required by this security profile"));
    let public_key = std::env::var("SKYLICENSE_MANIFEST_PUBLIC_KEY").unwrap_or_else(|_| {
        panic!("SKYLICENSE_MANIFEST_PUBLIC_KEY is required by this security profile")
    });
    let uses_ci_identity = build_id.eq_ignore_ascii_case(release_identity::CI_TEST_BUILD_ID_HEX)
        || public_key.eq_ignore_ascii_case(release_identity::CI_TEST_PUBLIC_KEY_HEX);

    match channel.as_str() {
        "production" => assert!(
            !uses_ci_identity,
            "known CI test identity cannot be used for a production native release"
        ),
        "ci-test" => assert!(
            build_id.eq_ignore_ascii_case(release_identity::CI_TEST_BUILD_ID_HEX)
                && public_key.eq_ignore_ascii_case(release_identity::CI_TEST_PUBLIC_KEY_HEX),
            "ci-test channel must use the pinned CI Build ID and manifest public key"
        ),
        _ => panic!("SKYLICENSE_ARTIFACT_CHANNEL must be either production or ci-test"),
    }
}

fn validate_optional_next_certificate_pin() {
    let Some(next) = std::env::var_os("SKYLICENSE_CERT_SHA256_NEXT") else {
        return;
    };
    let next = next
        .into_string()
        .unwrap_or_else(|_| panic!("SKYLICENSE_CERT_SHA256_NEXT must be valid UTF-8"));
    require_hex_32("SKYLICENSE_CERT_SHA256_NEXT", true);

    let primary = std::env::var("SKYLICENSE_CERT_SHA256").unwrap_or_else(|_| {
        panic!("SKYLICENSE_CERT_SHA256 is required when SKYLICENSE_CERT_SHA256_NEXT is set")
    });
    require_hex_32("SKYLICENSE_CERT_SHA256", true);
    assert!(
        !primary.eq_ignore_ascii_case(&next),
        "SKYLICENSE_CERT_SHA256_NEXT must differ from SKYLICENSE_CERT_SHA256"
    );
}

fn require_hex_32(name: &str, reject_zero: bool) {
    let value = std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required by this security profile"));
    assert!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name} must be exactly 64 hexadecimal characters"
    );
    assert!(
        !reject_zero || value.bytes().any(|byte| byte != b'0'),
        "{name} must not be all zero"
    );
}

fn require_positive_epoch(name: &str) -> u32 {
    let value = std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required by this security profile"));
    let epoch = value
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{name} must be a positive 32-bit integer"));
    assert!(epoch > 0, "{name} must be greater than zero");
    epoch
}
