use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct TimeApi {
    status: String,
    message: String,
    countryCode: String,
    countryName: String,
    regionName: String,
    cityName: String,
    zoneName: String,
    abbreviation: String,
    gmtOffset: i64,
    dst: String,
    zoneStart: i64,
    zoneEnd: i64,
    nextAbbreviation: String,
    pub timestamp: i64,
    formatted: String,
}

impl TimeApi {
    pub async fn get_atomic_time() -> Self {
        let request_url = "https://api.timezonedb.com/v2.1/get-time-zone?key=RQ6ZFDOXPVLR&format=json&by=zone&zone=Europe/Vienna".to_string();

        reqwest::get(&request_url)
            .await
            .expect("Failed to send request")
            .json()
            .await
            .expect("Failed to read response")
    }
}
