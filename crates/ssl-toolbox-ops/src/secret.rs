//! Secret material that crosses a front-end boundary.
//!
//! Passphrases enter this crate from somewhere less trustworthy than the crate
//! itself — a terminal prompt, or a webview where the value lived in a JS heap
//! we do not control. [`Secret`] narrows the blast radius of that fact:
//!
//! - it zeroes its buffer on drop, so a passphrase does not linger in freed
//!   heap memory for the life of the process;
//! - it refuses to `Serialize`, so a secret can never be reflected back out to
//!   a front-end, written into `state.json`, or captured in an audit entry;
//! - it redacts under `Debug`, so it cannot leak through an error chain or a
//!   stray log line.
//!
//! It does *not* protect against a compromised front-end, an attacker with
//! debugger access, or the OS swapping the process out. See ARCHITECTURE.md
//! §11 for what is and is not in scope.

use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A passphrase supplied by the user.
///
/// Deliberately one-way: deserializable so a front-end can hand one in, never
/// serializable so it cannot travel back out.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying passphrase to hand to `ssl-toolbox-core`.
    ///
    /// Keep the borrow as short-lived as possible and never copy it into a
    /// owned `String` that outlives the operation.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// An empty secret is treated as "no passphrase" for unencrypted inputs,
    /// matching the CLI's long-standing press-Enter-if-not-encrypted behavior.
    pub fn as_option(&self) -> Option<&str> {
        if self.0.is_empty() {
            None
        } else {
            Some(&self.0)
        }
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_formatting_does_not_leak_the_passphrase() {
        let secret = Secret::new("hunter2-correct-horse");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"));
        assert_eq!(rendered, "Secret(<redacted>)");
    }

    #[test]
    fn debug_of_a_struct_containing_a_secret_stays_redacted() {
        // Guards the realistic leak path: a request struct derives Debug and
        // gets logged or wrapped into an error chain.
        #[derive(Debug)]
        struct Request {
            #[allow(dead_code)]
            path: String,
            #[allow(dead_code)]
            password: Secret,
        }

        let rendered = format!(
            "{:?}",
            Request {
                path: "server.key".into(),
                password: Secret::new("s3cret-passphrase"),
            }
        );
        assert!(!rendered.contains("s3cret-passphrase"));
        assert!(rendered.contains("server.key"));
    }

    #[test]
    fn empty_secret_reads_as_no_passphrase() {
        assert_eq!(Secret::new("").as_option(), None);
        assert_eq!(Secret::new("pw").as_option(), Some("pw"));
    }
}
