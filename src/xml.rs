use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq)]
pub struct Radiko {
    pub stations: Stations,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Stations {
    #[serde(rename = "station")]
    pub stations: Vec<Station>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Station {
    #[serde(rename = "@id")]
    pub id: String,
    pub name: String,
    pub progs: Vec<Programs>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Date(String);

#[derive(Debug, Deserialize, PartialEq)]
pub struct Programs {
    pub date: Date,
    pub prog: Vec<Prog>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Prog {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@ft")]
    pub ft: String,
    #[serde(rename = "@to")]
    pub to: String,
    pub title: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Urls {
    #[serde(rename = "url")]
    pub url: Vec<Url>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Url {
    #[serde(rename = "@areafree")]
    pub areafree: String,
    #[serde(rename = "@timefree")]
    pub timefree: String,
    pub playlist_create_url: String,
}
