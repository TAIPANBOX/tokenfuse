use std::collections::HashMap;

use p256::ecdsa::signature::Signer as _;

use super::*;

const URL: &str = "https://keyryx.acme.example";

/// A file only the test with this label names: the lib tests share a process.
fn scratch(label: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tf-cloud-audit-keyryx-{label}-{}",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| map.get(k).cloned()
}

fn refusal(pairs: &[(&str, &str)]) -> String {
    match signer_from(env(pairs)) {
        Err(why) => why,
        Ok(None) => panic!("{pairs:?} must refuse to start, it read as signing off"),
        Ok(Some(_)) => panic!("{pairs:?} must refuse to start, it built a signer"),
    }
}

fn test_key() -> SigningKey {
    SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar")
}

/// The kid keyryx gives the P-256 key whose scalar is 32 bytes of `0x11`,
/// `0x22` and `0x33`. Written out, never computed here: @measured 2026-10-19 by
/// running keyryx's own path for an EC key, `kidFor` in
/// `internal/keystore/keystore.go` (keyryx 9bf76ec), which is
/// `delegation.Thumbprint(delegation.FromPublic(k, ""))` from agent-stack-go
/// v2.0.1 (e52e7fc), under go1.27.2. An expectation taken from the function
/// under test could not fail.
const KID_11: &str = "OEurnbzOGbRad4qOD9lNK8VYMQGvg5cmLnVKeydAqL4";
const KID_22: &str = "IYSTfWVkEEZyrkea6dxuW3QW2EKDRcVFfBIUXpYO0Rc";
const KID_33: &str = "iAzi3C-OjPVWNyPopGebSBzQGxyqWSYHSp2clxH5mSI";

/// keyryx's answer to a sign, as `internal/api` writes it, over `bytes`, by
/// `key`, naming `kid`.
fn answer_from(key: &SigningKey, kid: &str, alg: &str, bytes: &[u8], compressed: bool) -> Vec<u8> {
    let sig: Signature = key.sign(bytes);
    serde_json::json!({
        "alg": alg,
        "kid": kid,
        "signature_b64": STANDARD.encode(sig.to_bytes()),
        "public_key_b64": STANDARD.encode(key.verifying_key().to_encoded_point(compressed).as_bytes()),
    })
    .to_string()
    .into_bytes()
}

/// keyryx's answer by [`test_key`], under the kid keyryx gives it.
fn answer(alg: &str, bytes: &[u8], compressed: bool) -> Vec<u8> {
    answer_from(&test_key(), KID_11, alg, bytes, compressed)
}

// -- configuration ----------------------------------------------------------

/// Unset, or `env` in any case: today's in-process key, an unparseable one still
/// reading as signing off, and nothing set reading as off.
#[test]
fn unset_or_env_signs_with_the_in_process_key_as_before() {
    assert!(matches!(signer_from(env(&[])), Ok(None)));
    let raw = STANDARD.encode([0x11u8; 32]);
    for word in [None, Some("env"), Some(" ENV ")] {
        let mut pairs = vec![(AUDIT_SIGNING_KEY_ENV, raw.as_str())];
        if let Some(w) = word {
            pairs.push((SIGNER_ENV, w));
        }
        match signer_from(env(&pairs)) {
            Ok(Some(AuditSigner::Env(k))) => assert_eq!(k, test_key(), "{word:?}"),
            _ => panic!("{word:?} with a key must be the in-process signer"),
        }
        let mut garbage = vec![(AUDIT_SIGNING_KEY_ENV, "not a key !!!")];
        if let Some(w) = word {
            garbage.push((SIGNER_ENV, w));
        }
        assert!(
            matches!(signer_from(env(&garbage)), Ok(None)),
            "{word:?}: an unparseable key reads as signing off, as it always has"
        );
    }
}

/// A word the switch does not know refuses, naming the variable, the value and
/// the words it reads, rather than falling back to either signer.
#[test]
fn a_signer_word_it_cannot_read_refuses_to_start() {
    let why = refusal(&[(SIGNER_ENV, "keyrix")]);
    for name in [SIGNER_ENV, "keyrix", "env|keyryx"] {
        assert!(why.contains(name), "{why}");
    }
}

#[test]
fn keyryx_with_everything_configured_is_the_keyryx_signer() {
    let cred = scratch("complete", "sk-cloud-1\n");
    let built = signer_from(env(&[
        (SIGNER_ENV, "keyryx"),
        (KEYRYX_URL_ENV, "https://keyryx.acme.example/"),
        (KEYRYX_KEY_ENV, "tokenfuse-audit"),
        (KEYRYX_CREDENTIAL_FILE_ENV, cred.to_str().unwrap()),
    ]));
    let _ = std::fs::remove_file(&cred);
    match built {
        Ok(Some(AuditSigner::Keyryx(s))) => {
            assert_eq!(s.base_url(), URL, "the trailing slash is trimmed");
            assert_eq!(s.key_name(), "tokenfuse-audit");
        }
        Ok(_) => panic!("keyryx configured must build the keyryx signer"),
        Err(why) => panic!("keyryx configured must start: {why}"),
    }
}

/// keyryx with nothing else names each of the three variables it needs.
#[test]
fn keyryx_missing_its_variables_names_each_one() {
    let why = refusal(&[(SIGNER_ENV, "keyryx")]);
    for name in [KEYRYX_URL_ENV, KEYRYX_KEY_ENV, KEYRYX_CREDENTIAL_FILE_ENV] {
        assert!(why.contains(name), "{why}");
    }
}

/// One signer per manifest: keyryx beside an in-process key refuses, so a key an
/// operator meant to move out of this environment is not left in it.
#[test]
fn keyryx_beside_an_in_process_key_refuses_to_start() {
    let cred = scratch("both", "sk-cloud-1\n");
    let raw = STANDARD.encode([0x11u8; 32]);
    let why = refusal(&[
        (SIGNER_ENV, "keyryx"),
        (AUDIT_SIGNING_KEY_ENV, raw.as_str()),
        (KEYRYX_URL_ENV, URL),
        (KEYRYX_KEY_ENV, "tokenfuse-audit"),
        (KEYRYX_CREDENTIAL_FILE_ENV, cred.to_str().unwrap()),
    ]);
    let _ = std::fs::remove_file(&cred);
    assert!(why.contains(AUDIT_SIGNING_KEY_ENV), "{why}");
}

/// A keyryx variable set while the signer is not keyryx is set but unused,
/// which refuses rather than reading as off.
#[test]
fn keyryx_variables_without_the_keyryx_signer_refuse_to_start() {
    for word in [None, Some("env")] {
        let mut pairs = vec![(KEYRYX_URL_ENV, URL)];
        if let Some(w) = word {
            pairs.push((SIGNER_ENV, w));
        }
        let why = refusal(&pairs);
        assert!(
            why.contains(KEYRYX_URL_ENV) && why.contains(SIGNER_ENV),
            "{why}"
        );
    }
}

#[test]
fn a_keyryx_url_that_is_not_an_origin_is_refused() {
    let cred = scratch("url", "sk-cloud-1\n");
    for bad in [
        "keyryx.acme.example",
        "ftp://keyryx.acme.example",
        "https://keyryx.acme.example/v1",
        "https://keyryx.acme.example/?a=1",
        "https://user:pass@keyryx.acme.example",
    ] {
        let why = refusal(&[
            (SIGNER_ENV, "keyryx"),
            (KEYRYX_URL_ENV, bad),
            (KEYRYX_KEY_ENV, "tokenfuse-audit"),
            (KEYRYX_CREDENTIAL_FILE_ENV, cred.to_str().unwrap()),
        ]);
        assert!(why.contains(KEYRYX_URL_ENV), "{bad}: {why}");
        assert!(
            !why.contains("pass@"),
            "{bad}: a credential is never echoed: {why}"
        );
    }
    let _ = std::fs::remove_file(&cred);
}

#[test]
fn a_key_name_outside_keyryxs_grammar_or_its_reserved_space_is_refused() {
    let cred = scratch("name", "sk-cloud-1\n");
    for bad in [
        "Tokenfuse",
        "-audit",
        "audit key",
        "keyryx.delegation-root",
        &"a".repeat(65),
    ] {
        let why = refusal(&[
            (SIGNER_ENV, "keyryx"),
            (KEYRYX_URL_ENV, URL),
            (KEYRYX_KEY_ENV, bad),
            (KEYRYX_CREDENTIAL_FILE_ENV, cred.to_str().unwrap()),
        ]);
        assert!(why.contains(KEYRYX_KEY_ENV), "{bad}: {why}");
    }
    let _ = std::fs::remove_file(&cred);
}

/// A credential file that cannot be used refuses at startup, and the refusal
/// never repeats what the file holds.
#[test]
fn a_credential_file_that_cannot_be_used_is_refused_and_never_echoed() {
    let empty = scratch("cred-empty", " \n");
    let two = scratch("cred-two", "sk-secret-1 sk-secret-2\n");
    let gone = std::env::temp_dir().join("tf-cloud-audit-keyryx-no-such-file");
    for path in [&empty, &two, &gone] {
        let why = refusal(&[
            (SIGNER_ENV, "keyryx"),
            (KEYRYX_URL_ENV, URL),
            (KEYRYX_KEY_ENV, "tokenfuse-audit"),
            (KEYRYX_CREDENTIAL_FILE_ENV, path.to_str().unwrap()),
        ]);
        assert!(why.contains(KEYRYX_CREDENTIAL_FILE_ENV), "{why}");
        assert!(!why.contains("sk-secret"), "{why}");
    }
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_file(&two);
}

// -- keyryx's answer ----------------------------------------------------------

/// An answer that verifies is taken, and its public key is served as the
/// manifest promises it: uncompressed, whatever encoding keyryx sent.
#[test]
fn an_answer_that_verifies_is_taken_and_its_key_served_uncompressed() {
    let bytes = b"acme\x1f1\x1fabc\x1f2\x1f7";
    for compressed in [false, true] {
        let got = verify_answer(&answer("ES256", bytes, compressed), bytes)
            .unwrap_or_else(|e| panic!("compressed={compressed}: {e:?}"));
        assert_eq!(got.kid, KID_11, "compressed={compressed}");
        let pk = STANDARD.decode(&got.public_key_b64).unwrap();
        assert_eq!(pk.len(), 65, "uncompressed SEC1 point");
        assert_eq!(pk[0], 0x04);
        let vk = VerifyingKey::from_sec1_bytes(&pk).unwrap();
        let sig = Signature::from_slice(&STANDARD.decode(&got.signature_b64).unwrap()).unwrap();
        assert!(vk.verify(bytes, &sig).is_ok());
    }
}

/// keyryx signs with whatever its named key holds; a manifest is ES256, so any
/// other algorithm is a manifest not signed, never one served under a wrong label.
#[test]
fn an_answer_in_another_algorithm_is_refused() {
    let bytes = b"acme";
    for alg in ["ES384", "ML-DSA-65", "", "es256"] {
        let why = verify_answer(&answer(alg, bytes, false), bytes).unwrap_err();
        assert!(why.reason.contains("ES256"), "{alg}: {why:?}");
    }
    // What keyryx answered is named, but never a byte that could break a log line.
    let why = verify_answer(&answer("ES\n384\u{1b}", bytes, false), bytes).unwrap_err();
    assert!(why.reason.contains("'ES384'"), "{why:?}");
}

#[test]
fn a_signature_over_other_bytes_is_refused() {
    let raw = answer("ES256", b"acme\x1f0\x1f\x1f0\x1f1", false);
    let why = verify_answer(&raw, b"acme\x1f0\x1f\x1f0\x1f2").unwrap_err();
    assert!(why.reason.contains("does not verify"), "{why:?}");
}

/// A signature by one key presented with another key's public half.
#[test]
fn a_public_key_that_did_not_sign_is_refused() {
    let bytes = b"acme";
    let mut v: serde_json::Value = serde_json::from_slice(&answer("ES256", bytes, false)).unwrap();
    let other = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    v["public_key_b64"] = STANDARD
        .encode(other.verifying_key().to_encoded_point(false).as_bytes())
        .into();
    let why = verify_answer(v.to_string().as_bytes(), bytes).unwrap_err();
    assert!(why.reason.contains("does not verify"), "{why:?}");
}

/// The kid keyryx gives each of three keys, its RFC 7638 thumbprint, is taken,
/// whichever SEC1 encoding keyryx sent the key in.
#[test]
fn a_kid_that_is_the_keys_thumbprint_is_taken() {
    let bytes = b"acme\x1f5\x1f0a0b\x1f6\x1f7";
    for (scalar, kid) in [(0x11u8, KID_11), (0x22, KID_22), (0x33, KID_33)] {
        let key = SigningKey::from_slice(&[scalar; 32]).unwrap();
        for compressed in [false, true] {
            let got = verify_answer(&answer_from(&key, kid, "ES256", bytes, compressed), bytes)
                .unwrap_or_else(|e| panic!("{scalar:#x} compressed={compressed}: {e:?}"));
            assert_eq!(got.kid, kid);
        }
    }
}

/// A signature that verifies under the key keyryx sent, beside a kid that names
/// some other key, or no key in the form keyryx names one: refused, because an
/// auditor anchors the manifest's key by its kid in keyryx's published set.
#[test]
fn a_kid_that_names_another_key_is_refused() {
    let bytes = b"acme";
    let padded = format!("{KID_11}=");
    let std_alphabet = KID_33.replace('-', "+");
    let flipped = format!("P{}", &KID_11[1..]);
    let cases: [(&SigningKey, &str); 6] = [
        (&test_key(), KID_22),
        (&test_key(), &padded),
        (&test_key(), &flipped),
        (&test_key(), "kid-1"),
        (&test_key(), &KID_11.to_lowercase()),
        (
            &SigningKey::from_slice(&[0x33u8; 32]).unwrap(),
            &std_alphabet,
        ),
    ];
    for (key, kid) in cases {
        let Err(why) = verify_answer(&answer_from(key, kid, "ES256", bytes, false), bytes) else {
            panic!("kid {kid:?} must be refused");
        };
        assert!(why.reason.contains("kid"), "{kid}: {why:?}");
        assert!(why.reason.contains("thumbprint"), "{kid}: {why:?}");
    }
    // The route's answer names no value; the operator's log names the key's own.
    let why = verify_answer(
        &answer_from(&test_key(), KID_22, "ES256", bytes, false),
        bytes,
    )
    .unwrap_err();
    assert!(
        !why.reason.contains(KID_22) && !why.reason.contains(KID_11),
        "{why:?}"
    );
    assert!(
        why.detail.contains(KID_11) && why.detail.contains(KID_22),
        "{why:?}"
    );
    let why = verify_answer(
        &answer_from(&test_key(), "a\nb\u{1b}c", "ES256", bytes, false),
        bytes,
    )
    .unwrap_err();
    assert!(
        why.detail.contains("'abc'"),
        "a kid never breaks a log line: {why:?}"
    );
}

#[test]
fn an_answer_missing_a_field_is_refused_by_name() {
    let bytes = b"acme";
    let good: serde_json::Value = serde_json::from_slice(&answer("ES256", bytes, false)).unwrap();
    for (field, said) in [
        ("kid", "kid"),
        ("public_key_b64", "public key"),
        ("signature_b64", "signature"),
    ] {
        let mut v = good.clone();
        v.as_object_mut().unwrap().remove(field);
        let why = verify_answer(v.to_string().as_bytes(), bytes).unwrap_err();
        assert!(why.reason.contains(said), "{field}: {why:?}");
    }
    let why = verify_answer(b"<html>", bytes).unwrap_err();
    assert!(why.reason.contains("not JSON"), "{why:?}");
}

/// 200 seeded hostile answers: arbitrary bytes, a valid answer with one field
/// replaced by noise, and a valid answer whose kid differs from the key's
/// thumbprint in one character. None panics and none is taken. The valid answer
/// is checked first, so each case fails because of the field it breaks.
#[test]
fn hostile_answers_never_panic_and_never_verify() {
    let bytes = b"acme\x1f3\x1fdeadbeef\x1f4\x1f99";
    let good: serde_json::Value = serde_json::from_slice(&answer("ES256", bytes, false)).unwrap();
    assert!(verify_answer(good.to_string().as_bytes(), bytes).is_ok());
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for seed in 0..200 {
        let len = (next() % 300) as usize;
        let noise: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        assert!(
            verify_answer(&noise, bytes).is_err(),
            "seed {seed}: raw noise"
        );
        let mut v = good.clone();
        let field = ["alg", "kid", "signature_b64", "public_key_b64"][(next() % 4) as usize];
        // Only the key's thumbprint is its kid, so any other string breaks it too.
        v[field] = match next() % 3 {
            1 => serde_json::Value::from(next()),
            0 => STANDARD.encode(&noise).into(),
            _ => String::from_utf8_lossy(&noise).into_owned().into(),
        };
        assert!(
            verify_answer(v.to_string().as_bytes(), bytes).is_err(),
            "seed {seed}: {field} replaced"
        );
        // One character of the kid swapped for another base64url character.
        const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut kid = KID_11.as_bytes().to_vec();
        let at = (next() % kid.len() as u64) as usize;
        let mut c = B64URL[(next() % 64) as usize];
        if c == kid[at] {
            c = B64URL[(B64URL.iter().position(|&b| b == c).unwrap() + 1) % 64];
        }
        kid[at] = c;
        let mut v = good.clone();
        v["kid"] = String::from_utf8(kid).unwrap().into();
        assert!(
            verify_answer(v.to_string().as_bytes(), bytes).is_err(),
            "seed {seed}: kid off by one character at {at}"
        );
    }
}
