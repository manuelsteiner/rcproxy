use crate::options::DefaultFilterRule;
use crate::options::OPT;
use crate::HttpClient;
use gotham::handler::HandlerResult;
use gotham::helpers::http::response::create_response;
use gotham::hyper::header::{
    CONTENT_SECURITY_POLICY, SERVER, X_CONTENT_TYPE_OPTIONS, X_XSS_PROTECTION,
};
use gotham::hyper::{HeaderMap, StatusCode};
use gotham::router::builder::*;
use gotham::router::Router;
use gotham::state::{client_addr, FromState, State};
use hmac::{Hmac, Mac, NewMac};
use ipnet::IpNet;
use log::{debug, error, info};
use regex::Regex;
use sha2::Sha256;
use std::net::IpAddr;
use std::process::exit;
use std::str;
use url::Url;

lazy_static! {
    static ref CLIENT: HttpClient<'static> = {
        match HttpClient::new(
            OPT.max_redirects,
            OPT.timeout,
            OPT.max_size,
            &OPT.mime_regex,
            &OPT.proxy,
            &OPT.proxy_username,
            &OPT.proxy_password,
        ) {
            Ok(client) => client,
            Err(()) => {
                error!("Error initialising HTTP client. Exiting");
                exit(-1);
            }
        }
    };

    static ref HEADERS: HeaderMap = {
        let mut map = HeaderMap::new();
        map.insert(SERVER, OPT.server_name.parse().unwrap());
        map.insert(X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
        map.insert(X_XSS_PROTECTION, "1; mode=block".parse().unwrap());
        map.insert(CONTENT_SECURITY_POLICY, "default-src 'none'; img-src data:; style-src 'unsafe-inline'".parse().unwrap());

        if let Some(headers) = &OPT.headers {
            for (key, value) in headers {
                map.insert(key.as_str(), value.parse().unwrap());
            }
        }

        map
    };

    static ref IP_BLACKLIST: Vec<IpNet> = {
        let mut list = vec![
            // "127.0.0.0/8".parse::<IpNet>().unwrap(), // loopback
            "169.254.0.0/16".parse::<IpNet>().unwrap(), // ipv4 link local
            "10.0.0.0/8".parse::<IpNet>().unwrap(), // rfc1918
            "172.16.0.0/12".parse::<IpNet>().unwrap(), // rfc1918
            "192.168.0.0/16".parse::<IpNet>().unwrap(), // rfc1918
            // list.push("::1/128".parse::<IpNet>().unwrap(), // ipv6 loopback
            "fe80::/10".parse::<IpNet>().unwrap(), // ipv6 link local
            "fec0::/10".parse::<IpNet>().unwrap(), // deprecated ipv6 site-local
            "fc00::/7".parse::<IpNet>().unwrap(), // ipv6 ULA
            "::ffff:0:0/96".parse::<IpNet>().unwrap(), // IPv4-mapped IPv6 address
        ];

        if let Some(blacklist) = &OPT.blacklist_ip {
            for block in blacklist {
                list.push(block.parse::<IpNet>().unwrap());
            }
        }

        list
    };
}

#[derive(Deserialize, StateData, StaticResponseExtender)]
struct PathExtractor {
    digest: String,
    url: String,
}

pub fn setup() -> Router {
    debug!(
        "Initialising HTTP client with {} seconds timeout and {} maximum redirects.",
        OPT.timeout.to_string(),
        OPT.max_redirects.to_string()
    );
    lazy_static::initialize(&CLIENT);

    lazy_static::initialize(&HEADERS);

    lazy_static::initialize(&IP_BLACKLIST);

    debug!("Initialising HTTP server.");
    router()
}

fn router() -> Router {
    build_simple_router(|route| {
        route
            .get("/:digest/:url")
            .with_path_extractor::<PathExtractor>()
            .to_async(get_content_handler);
    })
}

fn add_headers(headers: &mut HeaderMap) {
    for (key, value) in HEADERS.iter() {
        headers.insert(key, value.clone());
    }
}

async fn get_content_handler(state: State) -> HandlerResult {
    let extractor = PathExtractor::borrow_from(&state);
    let headers = HeaderMap::borrow_from(&state);

    let mut response_bad_request = create_response(
        &state,
        StatusCode::BAD_REQUEST,
        mime::TEXT_PLAIN,
        "400 Bad Request",
    );

    let response_bad_request_headers = response_bad_request.headers_mut();
    add_headers(response_bad_request_headers);

    let mut response_not_found = create_response(
        &state,
        StatusCode::NOT_FOUND,
        mime::TEXT_PLAIN,
        "404 Not Found",
    );

    let response_not_found_headers = response_not_found.headers_mut();
    add_headers(response_not_found_headers);

    let mut response_internal_server_error = create_response(
        &state,
        StatusCode::INTERNAL_SERVER_ERROR,
        mime::TEXT_PLAIN,
        "500 Internal Server Error",
    );

    let response_internal_server_error_headers = response_internal_server_error.headers_mut();
    add_headers(response_internal_server_error_headers);

    let client_socket_address = match client_addr(&state) {
        Some(address) => address,
        None => {
            debug!("Error getting request client address.");
            return Ok((state, response_bad_request));
        }
    };

    let client_ip_address = client_socket_address.ip();

    debug!(
        "Checking request client address validity ({})",
        client_ip_address
    );

    if !validate_client_address(&client_ip_address, &IP_BLACKLIST) {
        debug!("The client address validation failed.");
        return Ok((state, response_bad_request));
    }

    debug!(
        "Handling content proxy request from client {} (User Agent: {}).",
        client_socket_address,
        headers["User-Agent"].to_str().unwrap_or("?")
    );

    debug!(
        "Checking request URL validity (Encoded: {}).",
        &extractor.url
    );

    let url = match decode_and_validate_url(&extractor.url, OPT.allow_https) {
        Ok(url) => url,
        Err(_error) => {
            debug!("The requested URL is invalid.");
            return Ok((state, response_bad_request));
        }
    };

    debug!("Checking content URL validity ({})", url);

    if !OPT.filters_allow.is_empty() || !OPT.filters_deny.is_empty() {
        match validate_content_url(
            &url,
            &OPT.filters_allow,
            &OPT.filters_deny,
            OPT.filter_default,
        ) {
            Ok(true) => (),
            Ok(false) => {
                debug!("Content URL {} is not allowed.", url);
                return Ok((state, response_not_found));
            }
            Err(_) => {
                debug!("Error checking content URL validity.",);
                return Ok((state, response_internal_server_error));
            }
        }
    }

    info!(
        "Client {} (User Agent: {}) requesting URL {}.",
        headers["Host"].to_str().unwrap_or("?"),
        headers["User-Agent"].to_str().unwrap_or("?"),
        url
    );

    debug!(
        "Checking HMAC validity (URL: {}, HMAC: {}).",
        url, &extractor.digest
    );

    if !validate_hmac(&url, &extractor.digest, &OPT.key) {
        debug!("The HMAC validation failed.");
        return Ok((state, response_bad_request));
    }

    let (mime, content) = match CLIENT.get(&url).await {
        Ok((mime, content)) => (mime, content),
        Err(StatusCode::NOT_FOUND) => return Ok((state, response_not_found)),
        Err(StatusCode::INTERNAL_SERVER_ERROR) => {
            return Ok((state, response_internal_server_error))
        }
        Err(_error) => return Ok((state, response_internal_server_error)),
    };

    debug!(
        "Serving requested URL {} to client {}.",
        url,
        headers["Host"].to_str().unwrap_or("?")
    );

    let mut response = create_response(&state, StatusCode::OK, mime, content);

    let response_headers = response.headers_mut();
    add_headers(response_headers);

    Ok((state, response))
}

fn validate_content_url(
    url: &str,
    filter_allow: &[String],
    filter_deny: &[String],
    filter_default: DefaultFilterRule,
) -> Result<bool, ()> {
    for allow in filter_allow {
        let regex = match Regex::new(allow) {
            Ok(regex) => regex,
            Err(_error) => {
                debug!("Discovered invalid regex during parsing.");
                return Err(());
            }
        };

        if regex.is_match(url) {
            debug!("Allow filter {} contains URL {}", allow, url);
            return Ok(true);
        }
    }

    for deny in filter_deny {
        let regex = match Regex::new(deny) {
            Ok(regex) => regex,
            Err(_error) => {
                debug!("Discovered invalid regex during parsing.");
                return Err(());
            }
        };

        if regex.is_match(url) {
            debug!("Deny filter {} contains URL {}", deny, url);
            return Ok(false);
        }
    }

    debug!(
        "No filter matched. Applying default allow rule: {}",
        filter_default
    );

    match filter_default {
        DefaultFilterRule::Allow => Ok(true),
        DefaultFilterRule::Deny => Ok(false),
    }
}

fn validate_client_address(address: &IpAddr, blacklist: &[IpNet]) -> bool {
    for block in blacklist.iter() {
        if block.contains(address) {
            debug!("Block {} contains client address {}", block, address);
            return false;
        }
    }

    true
}

fn decode_and_validate_url(encoded_url: &str, allow_https: bool) -> Result<String, ()> {
    let url = match hex::decode(encoded_url) {
        Ok(url) => url,
        Err(_error) => {
            debug!("URL parameter is not HEX encoded.");

            match base64::decode(encoded_url) {
                Ok(url) => url,
                Err(_error) => {
                    debug!("Malformed request (URL parameter is neither HEX nor Base64 encoded).");
                    return Err(());
                }
            }
        }
    };

    let url = match str::from_utf8(&url) {
        Ok(url) => url,
        Err(_error) => {
            debug!("Malformed request (URL parameter does not represent a string).");
            return Err(());
        }
    };

    let parsed_url = match Url::parse(&url) {
        Ok(url) => url,
        Err(_error) => {
            debug!("Malformed request (URL parameter is not a valid URL).");
            return Err(());
        }
    };

    return match parsed_url.scheme.as_str() {
        "http" => Ok(url.to_string()),
        "https" if allow_https => Ok(url.to_string()),
        "https" if !allow_https => {
            debug!("Invalid request (Proxying HTTPS URLs is disabled).");
            Err(())
        }
        _ => {
            debug!("Invalid request (URL parameter is neither HTTP nor HTTPS).");
            Err(())
        }
    };
}

fn validate_hmac(url: &str, digest: &str, key: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(url.as_bytes());

    let code = match hex::decode(digest) {
        Ok(code) => code,
        Err(_error) => {
            debug!("Malformed request (Digest parameter not Hex encoded).");
            return false;
        }
    };

    return match mac.verify(&code) {
        Ok(_url) => true,
        Err(_error) => {
            debug!("Invalid HMAC (The digest parameter does not match the digest computed from the URL with the provided secret key).");
            false
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_ip_blacklist() -> Vec<IpNet> {
        vec![
            // "127.0.0.0/8".parse::<IpNet>().unwrap(), // loopback
            "169.254.0.0/16".parse::<IpNet>().unwrap(), // ipv4 link local
            "10.0.0.0/8".parse::<IpNet>().unwrap(),     // rfc1918
            "172.16.0.0/12".parse::<IpNet>().unwrap(),  // rfc1918
            "192.168.0.0/16".parse::<IpNet>().unwrap(), // rfc1918
            // "::1/128".parse::<IpNet>().unwrap(), // ipv6 loopback
            "fe80::/10".parse::<IpNet>().unwrap(), // ipv6 link local
            "fec0::/10".parse::<IpNet>().unwrap(), // deprecated ipv6 site-local
            "fc00::/7".parse::<IpNet>().unwrap(),  // ipv6 ULA
            "::ffff:0:0/96".parse::<IpNet>().unwrap(), // IPv4-mapped IPv6 address
        ]
    }

    #[test]
    fn test_validate_content_url_allow() {
        let url = "https://www.example.com/image.png";
        let filters_allow = vec![".*example.com/.*".to_string()];
        let filters_deny = vec![".*example2.com/.*".to_string()];
        let default_filter = DefaultFilterRule::Deny;

        assert_eq!(
            validate_content_url(url, &filters_allow, &filters_deny, default_filter),
            Ok(true)
        )
    }

    #[test]
    fn test_validate_content_url_deny() {
        let url = "https://www.example2.com/image.png";
        let filters_allow = vec![".*example.com/.*".to_string()];
        let filters_deny = vec![".*example2.com/.*".to_string()];
        let default_filter = DefaultFilterRule::Allow;

        assert_eq!(
            validate_content_url(url, &filters_allow, &filters_deny, default_filter),
            Ok(false)
        )
    }

    #[test]
    fn test_validate_content_url_allow_default() {
        let url = "https://www.example3.com/image.png";
        let filters_allow = vec![".*example.com/.*".to_string()];
        let filters_deny = vec![".*example2.com/.*".to_string()];
        let default_filter = DefaultFilterRule::Allow;

        assert_eq!(
            validate_content_url(url, &filters_allow, &filters_deny, default_filter),
            Ok(true)
        )
    }

    #[test]
    fn test_validate_content_url_deny_default() {
        let url = "https://www.example3.com/image.png";
        let filters_allow = vec![".*example.com/.*".to_string()];
        let filters_deny = vec![".*example2.com/.*".to_string()];
        let default_filter = DefaultFilterRule::Deny;

        assert_eq!(
            validate_content_url(url, &filters_allow, &filters_deny, default_filter),
            Ok(false)
        )
    }

    #[test]
    fn test_validate_content_url_error() {
        let url = "https://www.example3.com/image.png";
        let filters_allow = vec!["[".to_string()];
        let filters_deny = vec![];
        let default_filter = DefaultFilterRule::Allow;

        assert_eq!(
            validate_content_url(url, &filters_allow, &filters_deny, default_filter),
            Err(())
        )
    }

    #[test]
    fn test_validate_client_address() {
        let client_address: IpAddr = "1.1.1.1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), true);
    }

    #[test]
    fn test_validate_client_address_ip4_loopback() {
        let client_address: IpAddr = "127.0.0.1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), true);
    }

    #[test]
    fn test_validate_client_address_ip6_loopback() {
        let client_address: IpAddr = "::1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), true);
    }

    #[test]
    fn test_validate_client_address_ip4_link_local() {
        let client_address: IpAddr = "169.254.0.1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), false);
    }

    #[test]
    fn test_validate_client_address_rfc1918() {
        let mut client_addresses: Vec<IpAddr> = Vec::new();
        client_addresses.push("10.0.0.1".parse().unwrap());
        client_addresses.push("172.16.0.1".parse().unwrap());
        client_addresses.push("192.168.0.1".parse().unwrap());

        let blacklist = create_ip_blacklist();

        for client_address in client_addresses.iter() {
            assert_eq!(validate_client_address(&client_address, &blacklist), false);
        }
    }

    #[test]
    fn test_validate_client_address_ip6_link_local() {
        let client_address: IpAddr = "fe80::1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), false);
    }

    #[test]
    fn test_validate_client_address_deprecated_ip6_site_local() {
        let client_address: IpAddr = "fec0::1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), false);
    }

    #[test]
    fn test_validate_client_address_ip6_ula() {
        let client_address: IpAddr = "fc00::1".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), false);
    }

    #[test]
    fn test_validate_client_address_ip4_mapped_ip6() {
        let client_address: IpAddr = "::ffff:0:2".parse().unwrap();
        let blacklist = create_ip_blacklist();

        assert_eq!(validate_client_address(&client_address, &blacklist), false);
    }

    #[test]
    fn test_decode_and_validate_url_base64_http() {
        let decoded_url = "http://www.google.com";
        let encoded_url = "aHR0cDovL3d3dy5nb29nbGUuY29t";
        let allow_https = true;

        assert_eq!(
            decode_and_validate_url(&encoded_url, allow_https),
            Ok(decoded_url.to_string())
        );
    }

    #[test]
    fn test_decode_and_validate_url_base64_https() {
        let decoded_url = "https://www.google.com";
        let encoded_url = "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ";
        let allow_https = true;

        assert_eq!(
            decode_and_validate_url(&encoded_url, allow_https),
            Ok(decoded_url.to_string())
        );
    }

    #[test]
    fn test_decode_and_validate_url_base64_invalid_base64() {
        // "https://www.google.com";
        let encoded_url = "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQi"; // last character added
        let allow_https = true;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_decode_and_validate_url_base64_invalid_url_format() {
        // "ftp://www.google.com";
        let encoded_url = "ZnRwOi8vd3d3Lmdvb2dsZS5jb20";
        let allow_https = true;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_decode_and_validate_url_base64_invalid_url_https_disabled() {
        // "https://www.google.com";
        let encoded_url = "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ";
        let allow_https = false;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_decode_and_validate_url_hex_http() {
        let decoded_url = "http://www.google.com";
        let encoded_url = "687474703A2F2F7777772E676F6F676C652E636F6D";
        let allow_https = true;

        assert_eq!(
            decode_and_validate_url(&encoded_url, allow_https),
            Ok(decoded_url.to_string())
        );
    }

    #[test]
    fn test_decode_and_validate_url_hex_https() {
        let decoded_url = "https://www.google.com";
        let encoded_url = "68747470733A2F2F7777772E676F6F676C652E636F6D";
        let allow_https = true;

        assert_eq!(
            decode_and_validate_url(&encoded_url, allow_https),
            Ok(decoded_url.to_string())
        );
    }

    #[test]
    fn test_decode_and_validate_url_hex_invalid_hex() {
        // "https://www.google.com";
        let encoded_url = "68747470733A2F2F7777772E676F6F676C652E636F6DG"; // last character added
        let allow_https = true;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_decode_and_validate_url_hex_invalid_url_format() {
        // "ftp://www.google.com";
        let encoded_url = "6674703A2F2F7777772E676F6F676C652E636F6D";
        let allow_https = true;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_decode_and_validate_url_hex_invalid_url_https_disabled() {
        // "https://www.google.com";
        let encoded_url = "68747470733A2F2F7777772E676F6F676C652E636F6D";
        let allow_https = false;

        assert_eq!(decode_and_validate_url(&encoded_url, allow_https), Err(()));
    }

    #[test]
    fn test_validate_hmac() {
        let url = "https://www.google.com";
        let digest = "5fe8a55870ffb6903ac0987bf70245b8c5e23eca66cd794c61788266c8972c1a";
        let key = "secret";

        assert_eq!(validate_hmac(&url, &digest, &key), true);
    }

    #[test]
    fn test_validate_hmac_invalid_hex() {
        let url = "https://www.google.com";
        // changed last character to invalid hex
        let digest = "5fe8a55870ffb6903ac0987bf70245b8c5e23eca66cd794c61788266c8972c1k";
        let key = "secret";

        assert_eq!(validate_hmac(&url, &digest, &key), false);
    }

    #[test]
    fn test_validate_hmac_invalid_code() {
        let url = "https://www.google.com";
        // changed last character to a different value
        let digest = "5fe8a55870ffb6903ac0987bf70245b8c5e23eca66cd794c61788266c8972c1b";
        let key = "secret";

        assert_eq!(validate_hmac(&url, &digest, &key), false);
    }
}
