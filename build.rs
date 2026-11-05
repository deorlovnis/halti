//! Test hooks (`HALTI_TEST_APPROVE`, the fake Keychain, path overrides) are compiled only into
//! builds with the debug profile, keyed to a cfg of their own, `halti_dev`. Debug assertions alone
//! aren't enough: a release profile can turn them on, and that build must still ignore the hooks.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(halti_dev)");
    println!("cargo::rerun-if-changed=build.rs");
    // "debug" for the dev and test profiles and those that inherit from them, "release" for the
    // rest (ci-release included).
    if std::env::var("PROFILE").as_deref() == Ok("debug") {
        println!("cargo::rustc-cfg=halti_dev");
    }
    // What `halti build-info` names as the build's target.
    println!("cargo::rustc-env=BUILD_TARGET={}", std::env::var("TARGET").unwrap_or_default());
}
