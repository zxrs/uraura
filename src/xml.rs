use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq)]
pub struct Radiko {
    pub ttl: Ttl,
    pub srvtime: SrvTime,
    pub stations: Stations,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Ttl {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct SrvTime {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Stations {
    #[serde(rename = "$value")]
    pub value: Vec<Station>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Station {
    pub id: String,
    pub name: Name,
    pub progs: Progs,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Name {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Date {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Progs {
    pub date: Date,
    #[serde(rename = "prog")]
    pub value: Vec<Prog_>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Prog_ {
    pub id: String,
    pub master_id: String,
    pub ft: String,
    pub to: String,
    pub ftl: String,
    pub tol: String,
    pub dur: String,
    pub title: Title,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Title {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Urls {
    #[serde(rename = "$value")]
    pub value: Vec<Url>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Url {
    pub areafree: String,
    pub max_delay: String,
    pub timefree: String,
    pub playlist_create_url: String,
}
