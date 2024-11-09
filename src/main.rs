use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::prelude::*;
use std::{collections::HashMap, env, fmt, io::Write, sync::Arc};
use tokio::{fs, process::Command, sync::Semaphore};

mod consts;
mod xml;

use consts::{Coodinate, Pref, COODINATES, FULLKEY_B64, VERSION_MAP};
use xml::*;

const DOWNLOAD_PROGRAMS: &[(&str, &str)] = &[
    ("ウラのウラまで浦川です", "URAURA"),
    ("兵動大樹のほわ～っとエエ感じ。", "HYODO"),
    ("Ｓｕｎｓｔａｒ　ｐｒｅｓｅｎｔｓ　浦川泰幸の健", "KENKO"),
    ("征平・吉弥の土曜も全開！！", "ZENKAI"),
    ("日曜落語～なみはや亭～", "NAMIHAYA"),
    ("宇野さんと小川さん。", "UO"),
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

    for program in programs.iter() {
        for (prefix, times) in program.iter() {
            let mut file_names = vec![];
            for (i, (ft, to)) in times.iter().enumerate() {
                let req = req.clone();
                let token = token.clone();
                let data = download(req, pref, token, ft.to_string(), to.to_string()).await?;
                let file_name = format!("/home/{}/Downloads/{prefix}_{}_{i}.aac", &user, &yyyymmdd);
                file_names.push(file_name.clone());
                fs::write(file_name, data).await?;
            }

            let list_name = format!("/home/{}/Downloads/{prefix}_{}_list.txt", &user, &yyyymmdd);
            fs::write(
                &list_name,
                &file_names
                    .iter()
                    .try_fold(vec![], |mut acc, n| -> Result<_> {
                        writeln!(&mut acc, "file {n}")?;
                        Ok(acc)
                    })?,
            )
            .await?;

            Command::new("ffmpeg")
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
                .arg(format!(
                    "/home/{}/Downloads/{prefix}_{}.aac",
                    &user, &yyyymmdd
                ))
                .spawn()?
                .wait()
                .await?;

            fs::remove_file(&list_name).await?;
            for file_name in file_names {
                fs::remove_file(file_name).await?;
            }
        }
    }
    Ok(())
}
