use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::prelude::*;
use std::{collections::HashMap, env, fmt, sync::Arc};
use tokio::sync::Semaphore;
use xml::reader::{EventReader, XmlEvent};

mod consts;
use consts::{Coodinate, Pref, COODINATES, FULLKEY_B64, VERSION_MAP};

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
        let mut rng = rand::thread_rng();
        let id = (0..32).map(|_| hex[rng.gen_range(0..hex.len())]).collect();
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
        let mut rng = rand::thread_rng();
        let version = VERSION_MAP[rng.gen_range(0..VERSION_MAP.len())].0;
        let sdk = version_map.get(version).unwrap().sdk;
        let builds = version_map.get(version).unwrap().builds;
        let build = builds[rng.gen_range(0..builds.len())];
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
    let mut rng = rand::thread_rng();
    let (pref, latlong) = &COODINATES[rng.gen_range(0..COODINATES.len())];
    let lat = latlong.0 + rng.gen_range(-0.025..0.025);
    let long = latlong.1 + rng.gen_range(-0.025..0.025);
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

async fn download(
    req: Arc<reqwest::Client>,
    pref: Pref,
    token: String,
    ft: String,
    to: String,
) -> Result<Vec<u8>> {
    let res = req
        .get(format!(
            "https://radiko.jp/v2/api/ts/playlist.m3u8?station_id=ABC&ft={ft}&to={to}"
        ))
        .header("X-Radiko-AreaId", pref.as_id())
        .header("X-Radiko-AuthToken", token)
        .send()
        .await?;

    let res = res.text().await?;
    let data_link = res
        .split('\n')
        .find(|d| !d.starts_with('#') && !d.trim().is_empty())
        .context("no data link.")?;

    //dbg!(data_link);

    let res = req.get(data_link).send().await?;
    let res = res.text().await?;
    let links: Vec<String> = res
        .split('\n')
        .filter_map(|d| {
            if !d.starts_with('#') && !d.trim().is_empty() {
                Some(d.to_string())
            } else {
                None
            }
        })
        .collect();

    let sem = Arc::new(Semaphore::new(16));
    let mut handles = vec![];
    for link in links {
        let permit = sem.clone().acquire_owned().await?;
        let req = req.clone();
        handles.push(tokio::spawn(async move {
            dbg!(&link);
            let data = req.get(link).send().await.unwrap().bytes().await.unwrap();
            let (offset, _) = parse_aac(&data);
            drop(permit);
            data.get(offset as usize..).unwrap().to_vec()
        }));
    }

    let mut buf = vec![];
    for handle in handles {
        buf.push(handle.await?);
    }
    Ok(buf.into_iter().flatten().collect())
}

#[tokio::main]
async fn main() -> Result<()> {
    let yyyymmdd = env::args().nth(1).context("no arg.")?;
    ensure!(
        yyyymmdd.len() == 8 && yyyymmdd.chars().all(|c| c.is_ascii_digit()),
        "invalid arg."
    );

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
    let parser = EventReader::new(xml.as_bytes());
    let mut programs = vec![];
    let mut ft = String::new();
    let mut to = String::new();
    for e in parser {
        match e {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => {
                if name.local_name.eq("station") && !attributes.iter().any(|a| a.value.eq("ABC")) {
                    break;
                }
                if name.local_name.eq("prog") {
                    for attr in attributes {
                        if attr.name.local_name.eq("ft") {
                            ft.clone_from(&attr.value);
                        }
                        if attr.name.local_name.eq("to") {
                            to.clone_from(&attr.value)
                        }
                    }
                }
            }
            Ok(XmlEvent::Characters(s))
                if s.starts_with("ウラのウラまで浦川です")
                    || s.starts_with("兵動大樹のほわ～っとエエ感じ。") =>
            {
                programs.push((ft.clone(), to.clone()));
            }
            _ => (),
        }
    }

    let mut file_names = vec![];
    for (i, (ft, to)) in programs.into_iter().enumerate() {
        let req = req.clone();
        let token = token.clone();
        let data = download(req, pref, token, ft, to).await?;
        let file_name = format!("URAURA_{}_{i}.aac", &yyyymmdd);
        file_names.push(file_name.clone());
        tokio::fs::write(file_name, data).await?;
    }

    let list_name = format!("URAURA_{}_list.txt", &yyyymmdd);
    tokio::fs::write(
        &list_name,
        file_names
            .iter()
            .map(|n| format!("file {n}\n"))
            .collect::<String>()
            .as_bytes(),
    )
    .await?;

    tokio::process::Command::new("ffmpeg")
        .arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-safe")
        .arg("0")
        .arg("-f")
        .arg("concat")
        .arg("-i")
        .arg(&list_name)
        .arg("-c:a")
        .arg("copy")
        .arg(format!("URAURA_{}.aac", &yyyymmdd))
        .spawn()?
        .wait()
        .await?;

    std::fs::remove_file(&list_name)?;
    file_names.iter().try_for_each(std::fs::remove_file)?;
    Ok(())
}
