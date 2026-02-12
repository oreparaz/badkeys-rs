/// Category of a known-bad key, indicating the source/reason it is compromised.
///
/// Category IDs must match those used in `scripts/generate_blocklist.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Category {
    /// Debian OpenSSL PRNG bug (CVE-2008-0166)
    DebianSsl = 0,
    /// Keys from RFC/IETF draft examples
    Rfc = 1,
    /// Keys from vendor documentation
    Documentation = 2,
    /// Keys from firmware (kompromat)
    Firmware = 3,
    /// Localhost certificate keys
    LocalhostCert = 4,
    /// Keys from software test suites
    SoftwareTests = 5,
    /// Cryptographic test vectors
    TestVectors = 6,
    /// Miscellaneous compromised keys
    Misc = 7,
    /// Private keys found in public git repositories
    GitKeys = 8,
    /// Private keys extracted from firmware images
    FirmwareKeys = 9,
    /// Private keys from software packages
    PackageKeys = 10,
    /// Private keys exposed on web servers
    WebKeys = 11,
    /// Keys from malware samples
    Malware = 12,
}

impl Category {
    /// Convert a raw category ID byte to a `Category`.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::DebianSsl),
            1 => Some(Self::Rfc),
            2 => Some(Self::Documentation),
            3 => Some(Self::Firmware),
            4 => Some(Self::LocalhostCert),
            5 => Some(Self::SoftwareTests),
            6 => Some(Self::TestVectors),
            7 => Some(Self::Misc),
            8 => Some(Self::GitKeys),
            9 => Some(Self::FirmwareKeys),
            10 => Some(Self::PackageKeys),
            11 => Some(Self::WebKeys),
            12 => Some(Self::Malware),
            _ => None,
        }
    }

    /// Short name for this category.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DebianSsl => "debianssl",
            Self::Rfc => "rfc",
            Self::Documentation => "documentation",
            Self::Firmware => "firmware",
            Self::LocalhostCert => "localhostcert",
            Self::SoftwareTests => "softwaretests",
            Self::TestVectors => "testvectors",
            Self::Misc => "misc",
            Self::GitKeys => "gitkeys",
            Self::FirmwareKeys => "fwkeys",
            Self::PackageKeys => "pkgkeys",
            Self::WebKeys => "webkeys",
            Self::Malware => "malware",
        }
    }

    /// Human-readable description of why keys in this category are compromised.
    pub fn description(&self) -> &'static str {
        match self {
            Self::DebianSsl => "Debian OpenSSL PRNG bug (CVE-2008-0166)",
            Self::Rfc => "Example key published in an RFC or IETF draft",
            Self::Documentation => "Example key from vendor documentation",
            Self::Firmware => "Private key embedded in firmware (kompromat)",
            Self::LocalhostCert => "Hardcoded localhost certificate key",
            Self::SoftwareTests => "Private key from a software test suite",
            Self::TestVectors => "Cryptographic test vector key",
            Self::Misc => "Miscellaneous compromised key",
            Self::GitKeys => "Private key committed to a public git repository",
            Self::FirmwareKeys => "Private key extracted from firmware images",
            Self::PackageKeys => "Private key found in a software package",
            Self::WebKeys => "Private key exposed on a web server",
            Self::Malware => "Key associated with malware",
        }
    }
}
