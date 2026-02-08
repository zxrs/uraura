use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Local, TimeDelta, TimeZone};
use rand::prelude::*;
use std::{
    collections::HashMap,
    env, fmt,
    io::{Read, Write},
    sync::Arc,
};
use tokio::{fs, process::Command};

mod consts;
mod xml;

use consts::{COODINATES, Coodinate, FULLKEY_B64, Pref, VERSION_MAP};
use xml::*;

const DOWNLOAD_PROGRAMS: &[(&str, &str)] = &[
    // MON~THR 15:00~
    ("ウラのウラまで浦川です", "URAURA"),
    // FRI 12:00~
    ("兵動大樹のほわ～っとエエ感じ。", "HYODO"),
    // SAT 9:30~
    ("Ｓｕｎｓｔａｒ　ｐｒｅｓｅｎｔｓ　浦川泰幸の健", "KENKO"),
    // SAT 10:00~
    ("征平・吉弥の土曜も全開！！", "ZENKAI"),
    // SUN 8:30~
    ("日曜落語～なみはや亭～", "NAMIHAYA"),
    // SUN 9:00~
    ("宇野さんと小川さん。", "UO"),
    // MON~SAT 2:00~
    ("Ｒ→９３３", "R933"),
];

async fn token() -> Result<(Pref, String)> {
    let info = random_info();
    let auth1 = reqwest::ClientBuilder::new().cookie_store(true).build()?;
    let useragent = info.useragent.to_string();
    let res = auth1
        .get("https://radiko.jp/v2/api/auth1")
        .header("User-Agent", &useragent)
        .header("X-Radiko-App", "aSmartPhone7a")
        .header("X-Radiko-App-Version", "7.5.0")
        .header("X-Radiko-Device", info.device.as_str())
        .header("X-Radiko-User", info.userid.as_str())
        .send()
        .await?;

    let headers = res.headers();

    let token = headers
        .get("x-radiko-authtoken")
        .context("no token")?
        .to_str()?;
    let offset = headers
        .get("x-radiko-keyoffset")
        .context("no keyoffset")?
        .to_str()?
        .parse::<usize>()?;
    let length = headers
        .get("x-radiko-keylength")
        .context("no length")?
        .to_str()?
        .parse::<usize>()?;

    let decoded = general_purpose::STANDARD.decode(FULLKEY_B64)?;
    let decoded = decoded.get(offset..offset + length).context("no content")?;
    let partial = general_purpose::STANDARD.encode(decoded);

    let (pref, coodinate) = gps();
    let auth2 = reqwest::ClientBuilder::new().cookie_store(true).build()?;
    let _res = auth2
        .get("https://radiko.jp/v2/api/auth2")
        .header("User-Agent", useragent)
        .header("X-Radiko-App", "aSmartPhone7a")
        .header("X-Radiko-App-Version", "7.5.0")
        .header("X-Radiko-AuthToken", token)
        .header("X-Radiko-Device", "31.SC-01J")
        .header("X-Radiko-User", info.userid.as_str())
        .header("X-Radiko-Location", coodinate.to_string())
        .header("X-Radiko-Connection", "wifi")
        .header("X-Radiko-Partialkey", partial)
        .send()
        .await?;
    Ok((pref, token.into()))
}

struct Info {
    userid: UserId,
    useragent: UserAgent,
    device: String,
}

struct UserId(String);

impl UserId {
    fn new() -> Self {
        let hex = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let mut rng = rand::rng();
        let id = (0..32)
            .map(|_| hex[rng.random_range(0..hex.len())])
            .collect();
        Self(id)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

struct UserAgent {
    version: &'static str,
    build: &'static str,
    sdk: &'static str,
}

impl UserAgent {
    fn new() -> Self {
        let version_map = HashMap::from(VERSION_MAP);
        let mut rng = rand::rng();
        let version = VERSION_MAP[rng.random_range(0..VERSION_MAP.len())].0;
        let sdk = version_map.get(version).unwrap().sdk;
        let builds = version_map.get(version).unwrap().builds;
        let build = builds[rng.random_range(0..builds.len())];
        Self {
            version,
            build,
            sdk,
        }
    }
}

impl fmt::Display for UserAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Dalvik/2.1.0 (Linux; U; Android {}; SC-02H/{})",
            self.version, self.build
        )
    }
}

fn random_info() -> Info {
    let userid = UserId::new();
    let useragent = UserAgent::new();
    let sdk = useragent.sdk;
    Info {
        userid,
        useragent,
        device: format!("{sdk}.SC-02H"),
    }
}

fn gps() -> (Pref, Coodinate) {
    let mut rng = rand::rng();
    let (pref, latlong) = &COODINATES[rng.random_range(0..COODINATES.len())];
    let lat = latlong.0 + rng.random_range(-0.025..0.025);
    let long = latlong.1 + rng.random_range(-0.025..0.025);
    (pref.to_owned(), Coodinate(lat, long))
}

fn parse_aac(data: &[u8]) -> (u32, u32) {
    if !data.starts_with(b"id3") {
        return (0, 0);
    }
    let id3_payload_size = u32::from_be_bytes(data[6..].try_into().unwrap());
    let id3_tag_size = 10 + id3_payload_size;

    let timestamp_low = u32::from_be_bytes(data[id3_tag_size as usize - 4..].try_into().unwrap());
    let timestamp_high = u32::from_be_bytes(data[id3_tag_size as usize - 8..].try_into().unwrap());
    let timestamp = timestamp_low + 0xffffffff * timestamp_high;
    (id3_tag_size, timestamp)
}

async fn yyyymmdd() -> Result<String> {
    if let Some(v) = env::args().nth(1) {
        ensure!(
            v.len() == 8 && v.chars().all(|c| c.is_ascii_digit()),
            "invalid date."
        );
        return Ok(v);
    }
    let result = String::from_utf8(Command::new("date").arg("+%Y%m%d").output().await?.stdout)?;
    let result = result.trim();
    ensure!(!result.is_empty(), "no yyyymmdd.");
    Ok(result.into())
}

async fn user() -> Result<String> {
    let user = Command::new("whoami").output().await?.stdout;
    Ok(String::from_utf8(user)?.split_whitespace().collect())
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
struct Time(DateTime<Local>);

impl Time {
    fn new(time: DateTime<Local>) -> Self {
        Self(time)
    }

    fn add_sec(self, sec: i64) -> Result<Self> {
        Ok(Self::new(
            self.0
                .checked_add_signed(TimeDelta::seconds(sec))
                .context("no time")?,
        ))
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format("%Y%m%d%H%M%S"))
    }
}

impl TryFrom<&str> for Time {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let year = value.get(0..4).context("no year")?.parse()?;
        let month = value.get(4..6).context("no month")?.parse()?;
        let day = value.get(6..8).context("no day")?.parse()?;
        let hour = value.get(8..10).context("no hour")?.parse()?;
        let min = value.get(10..12).context("no min")?.parse()?;
        let sec = value.get(12..14).context("no sec")?.parse()?;
        let date_time = Local
            .with_ymd_and_hms(year, month, day, hour, min, sec)
            .single()
            .context("no local time")?;
        Ok(Time::new(date_time))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let yyyymmdd = yyyymmdd().await?;
    let user = user().await?;
    let download_programs: Vec<_> = DOWNLOAD_PROGRAMS
        .iter()
        .filter(|(_, prefix)| {
            !std::path::Path::new(&format!(
                "/home/{}/Downloads/{}_{}.aac",
                &user, prefix, &yyyymmdd
            ))
            .exists()
        })
        .collect();

    let (pref, token) = token().await?;
    let req = reqwest::ClientBuilder::new().cookie_store(true).build()?;
    let req = Arc::new(req);

    let res = req
        .get(format!(
            "https://radiko.jp/v3/program/date/{}/JP27.xml",
            &yyyymmdd
        ))
        .header("X-Radiko-AreaId", pref.as_id())
        .header("X-Radiko-AuthToken", &token)
        .send()
        .await?;
    let xml = res.text().await?;
    let radiko: Radiko = serde_xml_rs::from_str(&xml)?;
    //dbg!(radiko);

    let programs: Vec<Vec<_>> = radiko
        .stations
        .value
        .iter()
        .filter(|s| s.id.eq("ABC"))
        .map(|s| &s.progs.value)
        .map(|programs| {
            download_programs
                .iter()
                .filter_map(|d| {
                    if programs.iter().any(|p| p.title.value.starts_with(d.0)) {
                        return Some((
                            d.1,
                            programs
                                .iter()
                                .filter_map(|p| {
                                    if p.title.value.starts_with(d.0) {
                                        return Some((p.ft.clone(), p.to.clone()));
                                    }
                                    None
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }
                    None
                })
                .collect()
        })
        .inspect(|t| {
            dbg!(&t);
        })
        .collect();

    //dbg!(programs);

    let res = req
        .get("https://radiko.jp/v3/station/stream/pc_html5/ABC.xml")
        .send()
        .await?;
    let xml = res.text().await?;
    let urls: Urls = serde_xml_rs::from_str(&xml)?;
    let playlist_url = urls
        .value
        .iter()
        .filter(|url| url.areafree.eq("0") && url.timefree.eq("1"))
        .map(|url| url.playlist_create_url.as_str())
        // .inspect(|v| println!("{v}"))
        .next()
        .unwrap_or("https://tf-f-rpaa-radiko.smartstream.ne.jp/tf/playlist.m3u8");

    let lsid: String = {
        let mut buf = [0; 32];
        std::fs::File::open("/dev/random")?.read_exact(&mut buf)?;
        let hex = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        buf.into_iter().map(|v| hex[v as usize / 16]).collect()
    };

    const FIXED_SEEK: i64 = 300;

    for program in programs.iter() {
        for (prefix, times) in program.iter() {
            let mut links = vec![];
            for (from, to) in times {
                let from: Time = from.as_str().try_into()?;
                let to: Time = to.as_str().try_into()?;

                let mut seek = from.clone();
                //println!("{from}, {to}");

                while seek < to {
                    let url = format!(
                        "{}?lsid={}&station_id=ABC&l={FIXED_SEEK}&start_at={}&end_at={}&type=b&ft={2}&to={3}&seek={}",
                        &playlist_url, &lsid, &from, &to, &seek
                    );

                    let res = req
                        .get(&url)
                        .header("X-Radiko-AreaId", pref.as_id())
                        .header("X-Radiko-AuthToken", &token)
                        .send()
                        .await?;
                    let res = res.text().await?;
                    let url = res
                        .lines()
                        .find(|s| !s.starts_with("#") && !s.trim().is_empty())
                        .context("no url")?;

                    let res = req.get(url).send().await?;
                    let res = res.text().await?;
                    let part_links: Vec<_> = res
                        .lines()
                        .filter(|s| !s.starts_with("#") && !s.trim().is_empty())
                        .map(|s| s.to_owned())
                        .collect();
                    // dbg!(url);

                    links.push(part_links);

                    seek = seek.add_sec(FIXED_SEEK)?;
                }
            }
            let mut buf: Vec<u8> = vec![];
            for url in links.iter().flatten() {
                dbg!(url);
                let data = req.get(url).send().await?.bytes().await?;
                let (offset, _) = parse_aac(&data);
                buf.write_all(data.get(offset as usize..).context("no data")?)?;
            }
            fs::write(
                format!("/home/{}/Downloads/{}_{}.aac", &user, prefix, &yyyymmdd),
                &buf,
            )
            .await?;
        }
    }
    Ok(())
}
