// @trace TASK-069
// @trace FR-009

use holonomy_core::auth::jwt_validator::JwtValidator;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSnRoLqL83W4CP
Vmo+/3FWu9/KAhdgDCbviN7kwlX1ilWU4rG/xoZ4oue3Fw/ve7d1DrRquC16u6Jw
641YPqBl1NHPvTojk1wshRoaqsV6R8ztL9Ykgi5M0gi7LiT8Ed10P3PJ+j+rX7S6
NNWvnclzoF1D5q4F9kBbCbX/fSySxRbQD97wo/e2baKJwecNhTNwsWLwAisBEHyG
5iJ0v9VBwfBuDm7YCEawpfENiMp7Hlf6ngm30hfHdgk5KZJY7sT8sFMa0sJcF/Ay
C7iC9eKPx71Bceuyy1UXoifqGB9P7I/59xvqwIw7AyNLbHpo7zrn2oX0r2bpx8Pk
tszpwxB9AgMBAAECggEAQEjSb9eYUcm8kkOil0r5qasbkfmUb+0Vn0xMGE/W0+Te
3VxaO7pZRg4XItPHueWtp+2OlPpVa15FJSlIkbQ/2gUc60cLLVunqTEROC2CrCGp
Q4Yz2x3fCvSa1KMvh77eNMK/UVlwQJssOx+wT3OeTwwWG4kX+drhZsguhGaNCdjP
ZtaMONj6O8bLvsHsQ24QsqBKaouPvx5rkMRg9n70qfrilTl4cRjriUNzejAxqfPa
/zu8meG1wap01t0csJXhkezKgczMINSsx89a+Jr1r4584K6kxHE4ru0gIdqOwwhq
rqUW+Xw3pSccEPsPg5yAizmrGb9DSjDNdaJ+zve20wKBgQD3X6y2T6rm3jA+ab/f
x9tL4ltUXPJnKT7nrJWpQdsW2QyR4W6jrYDnx5AHCh2U04gV4HtKmOC0QQAzWZ3h
+j5ZpXtocx1f99OpONnnF89Tx+ZVe3hpk/pGufue6nFFqh6UoqmJ3j98NIm27IJw
tj/vvg/PTEyDXyfq+g02CGoMrwKBgQDZ9URivqlCB5WyBJYphvdpmrl7cNJLK6/J
X1XBhuYpi9m6GmQFATaGjJiqbqsQ3zs6d5NZiyTdsboPa7ArFCQqqcrcyZ5jP1ql
c/zEicHhY97DcqrXUgOjPYLrEXHSOUvotOpHDZH/ryiIQyd8hG1RtNY4jl0hHldk
EUfAUEC4kwKBgQDuqnI6GzcqM2icbu7eezaLSkMPa/W7rkGwyARFHvLAYn0MKlHS
vU1HUnUVNZ9Ava3oXYLWgBUcFDKbWHVJV2TcnRoptha7RqIB/IXPvlsb3BvQkaWl
R04K+tlXg53xtqZ2hVHJYJIjxZSw1hMrp8qcBeW+/UA854vd247veMLIpQKBgGiR
RTfipS2qmeUIUkqmF/kwZCCW5i1uTi3ccTYh1DbGg7THiIjmJhSzS2MpKSU1FCNe
zvC80vkRlWRkk+Z3CUr2nv8CM90FviV22iQouz25PlyinNgk3t3oWvEQM31aQ9Ln
SSbBmfQDQvzsyvrwRcpXahdEJeYHuoGl0LixR/vFAoGAMwt3J7BHIkyFj7v5a6kz
RpWoHnqbtuQlU7AaliKSwUvs7I6a3jvN0yyg6SCAu6AuVsAPk/hly3KmesBjWwgc
herYn4DWIuaFFZ3yO+e4C76uVXtLoFVSCenzZaJpJRrg8igG9YQuUay3p3zZnP7G
/TVGBM5MEjR5MQkpcc8OiGE=
-----END PRIVATE KEY-----"#;

const JWK_N: &str = "0p0aC6i_N1uAj1ZqPv9xVrvfygIXYAwm74je5MJV9YpVlOKxv8aGeKLntxcP73u3dQ60argteruicOuNWD6gZdTRz706I5NcLIUaGqrFekfM7S_WJIIuTNIIuy4k_BHddD9zyfo_q1-0ujTVr53Jc6BdQ-auBfZAWwm1_30sksUW0A_e8KP3tm2iicHnDYUzcLFi8AIrARB8huYidL_VQcHwbg5u2AhGsKXxDYjKex5X-p4Jt9IXx3YJOSmSWO7E_LBTGtLCXBfwMgu4gvXij8e9QXHrsstVF6In6hgfT-yP-fcb6sCMOwMjS2x6aO8659qF9K9m6cfD5LbM6cMQfQ";
const JWK_E: &str = "AQAB";
const KID: &str = "test-key-1";

#[derive(Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,
    email: String,
    groups: Vec<String>,
}

#[tokio::test]
async fn test_jwt_validator_success() {
    let mut server = mockito::Server::new_async().await;

    let jwks_response = serde_json::json!({
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "kid": KID,
                "n": JWK_N,
                "e": JWK_E,
            }
        ]
    });

    let mock = server
        .mock("GET", "/keys")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_response.to_string())
        .create_async()
        .await;

    let jwks_url = format!("{}/keys", server.url());
    let validator = JwtValidator::new(
        jwks_url,
        "holonomy".to_string(),
        "https://myidp.com".to_string(),
    );

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600;

    let claims = TestClaims {
        sub: "user_123".to_string(),
        iss: "https://myidp.com".to_string(),
        aud: "holonomy".to_string(),
        exp,
        email: "alice@example.com".to_string(),
        groups: vec!["analyst".to_string(), "marketing".to_string()],
    };

    let encoding_key = EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let user_context = validator
        .validate_token(&token)
        .await
        .expect("Validation failed");

    assert_eq!(user_context.sub, Some("user_123".to_string()));
    assert_eq!(user_context.email.as_deref(), Some("alice@example.com"));
    assert_eq!(
        user_context.principals,
        vec!["analyst", "marketing", "user_123"]
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn test_jwt_validator_wrong_audience() {
    let mut server = mockito::Server::new_async().await;

    let jwks_response = serde_json::json!({
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "kid": KID,
                "n": JWK_N,
                "e": JWK_E,
            }
        ]
    });

    server
        .mock("GET", "/keys")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_response.to_string())
        .create_async()
        .await;

    let jwks_url = format!("{}/keys", server.url());
    let validator = JwtValidator::new(
        jwks_url,
        "holonomy".to_string(),
        "https://myidp.com".to_string(),
    );

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600;

    let claims = TestClaims {
        sub: "user_123".to_string(),
        iss: "https://myidp.com".to_string(),
        aud: "WRONG_AUDIENCE".to_string(),
        exp,
        email: "alice@example.com".to_string(),
        groups: vec!["analyst".to_string()],
    };

    let encoding_key = EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let res = validator.validate_token(&token).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("JWT validation failed"));
}
