use std::fmt;

include!("key.rs");

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Pref {
    Osaka,
    Hyogo,
    Nara,
    Kyoto,
}

impl Pref {
    pub fn as_id(&self) -> &'static str {
        use Pref::*;
        match self {
            Osaka => "JP27",
            Hyogo => "JP28",
            Nara => "JP29",
            Kyoto => "JP26",
        }
    }
}

use Pref::*;

pub struct Coodinate(pub f32, pub f32);

impl fmt::Display for Coodinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6},{:.6},gps", self.0, self.1)
    }
}

pub const COODINATES: [(Pref, Coodinate); 4] = [
    (Osaka, Coodinate(34.686_3, 135.519_67)),
    (Hyogo, Coodinate(34.691_27, 135.183_07)),
    (Nara, Coodinate(34.685_334, 135.832_75)),
    (Kyoto, Coodinate(35.021_247, 135.755_6)),
];

pub const VERSION_MAP: [(&str, Version); 4] = [
    (
        "7.0.0",
        Version {
            sdk: "24",
            builds: &[
                "NBD92Q", "NBD92N", "NBD92G", "NBD92F", "NBD92E", "NBD92D", "NBD91Z", "NBD91Y",
                "NBD91X", "NBD91U", "N5D91L", "NBD91P", "NRD91K", "NRD91N", "NBD90Z", "NBD90X",
                "NBD90W", "NRD91D", "NRD90U", "NRD90T", "NRD90S", "NRD90R", "NRD90M",
            ],
        },
    ),
    (
        "8.0.0",
        Version {
            sdk: "26",
            builds: &["5650811", "5796467", "5948681", "6107732", "6127070"],
        },
    ),
    (
        "10.0.0",
        Version {
            sdk: "29",
            builds: &["5933585", "6969601", "7023426", "7070703"],
        },
    ),
    (
        "12.0.0",
        Version {
            sdk: "31",
            builds: &[
                "SD1A.210817.015.A4",
                "SD1A.210817.019.B1",
                "SD1A.210817.037",
                "SQ1D.220105.007",
            ],
        },
    ),
];

pub struct Version {
    pub sdk: &'static str,
    pub builds: &'static [&'static str],
}
