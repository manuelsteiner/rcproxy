use ipnet::IpNet;
use log::LevelFilter;
use std::collections::HashMap;
use std::process::exit;
use std::result::Result::Ok;
use structopt::clap::arg_enum;
use structopt::StructOpt;

lazy_static! {
    pub static ref OPT: Opt = {
        let mut opt = Opt::from_args();

        opt.headers = match opt.header.clone() {
            Some(headers) => {
                match create_header_map(&headers) {
                    Ok(headers) => Some(headers),
                    Err(_error) => {
                        eprintln!("Error parsing additional response headers from arguments. Exiting.");
                        exit(1);
                    }
                }
            }
            None => None,
        };


        // TODO: probably no way around clone() here?
        if let Some(blacklist) = opt.blacklist_ip.clone() {
            let mut blacklist = blacklist;

            if blacklist.len() == 1 {
                blacklist = split_coma_separated_list(blacklist[0].as_str());
            }

            if !validate_ip_blacklist(&blacklist) {
                eprintln!("Error parsing client IP blacklist. Exiting.");
                exit(1);
            }

            opt.blacklist_ip = Some(blacklist)
        }

        // TODO: probably no way around clone() here?
        if let Some(filters) = opt.filter_url.clone() {
            let mut filters = filters;

            if filters.len() == 1 {
                filters = split_coma_separated_list(filters[0].as_str());
            }

            match validate_and_extract_filters(&filters) {
                Ok((allow, deny)) => {
                    opt.filters_allow = allow;
                    opt.filters_deny = deny;
                },
                Err(_) => {
                    eprintln!("Error parsing URL filters. Exiting.");
                exit(1);
                }
            }
        }

        if opt.mime.len() == 1 {
            opt.mime = split_coma_separated_list(opt.mime[0].as_str());
        }

        opt.mime_regex = create_mime_regex(&opt.mime);

        opt
    };
}

/// A content proxy to securely serve http assets
#[derive(Debug, StructOpt)]
#[structopt(name = "rcproxy")]
pub struct Opt {
    /// The address the proxy server binds to
    #[structopt(short, long, default_value = "127.0.0.1:80", env = "RCPROXY_ADDRESS")]
    pub address: String,

    /// The server name that is set in response headers
    #[structopt(
        short = "n",
        long,
        default_value = "rcproxy",
        env = "RCPROXY_SERVER_NAME"
    )]
    pub server_name: String,

    /// Additional response headers (<key>: <value>)
    #[structopt(short = "H", long)]
    pub header: Option<Vec<String>>,

    // Header map for easy header addition
    #[structopt(skip)]
    pub headers: Option<HashMap<String, String>>,

    /// Client IP ranges to blacklist (coma separated in environment variable)
    #[structopt(short, long, env = "RCPROXY_BLACKLIST_IP")]
    pub blacklist_ip: Option<Vec<String>>,

    /// Target URLs, from which content is allowed or denied (<a|d>:<regex> (a = allow, d = deny), allow takes priority, coma separated in environment variable)
    #[structopt(short, long, requires_all = &["filter-default"], env = "RCPROXY_FILTER_URL")]
    pub filter_url: Option<Vec<String>>,

    // The allow filter URL regex list
    #[structopt(skip)]
    pub filters_allow: Vec<String>,

    // The deny filter URL regex list
    #[structopt(skip)]
    pub filters_deny: Vec<String>,

    /// The default filter rule
    #[structopt(short = "d", long, possible_values = &DefaultFilterRule::variants(),
    case_insensitive = true, default_value = "Allow", env = "RCPROXY_FILTER_DEFAULT")]
    pub filter_default: DefaultFilterRule,

    /// The HMAC key to authenticate requests
    #[structopt(short, long, env = "RCPROXY_KEY")]
    pub key: String,

    /// Allow proxying of HTTPS assets
    #[structopt(short = "s", long)]
    pub allow_https: bool,

    /// Maximum content size (in bytes), 0 equals unlimited
    #[structopt(short = "c", long, default_value = "0", env = "RCPROXY_MAX_SIZE")]
    pub max_size: u32,

    /// Maximum number of redirects to follow when fetching content
    #[structopt(short = "r", long, default_value = "5", env = "RCPROXY_MAX_REDIRECTS")]
    pub max_redirects: u8,

    /// Connection timeout length when fetching content (in seconds)
    #[structopt(short, long, default_value = "5", env = "RCPROXY_TIMEOUT")]
    pub timeout: u8,

    /// Proxy to use when fetching content
    #[structopt(short, long, env = "RCPROXY_PROXY")]
    pub proxy: Option<String>,

    /// Proxy username to use when fetching content via proxy
    #[structopt(long, requires_all = &["proxy", "proxy-password"], env = "RCPROXY_PROXY_USERNAME")]
    pub proxy_username: Option<String>,

    /// Proxy password to use when fetching content via proxy
    #[structopt(long, requires_all = &["proxy", "proxy-username"], env = "RCPROXY_PROXY_PASSWORD")]
    pub proxy_password: Option<String>,

    /// Mime types that will be proxied (coma separated in environment variable)
    #[structopt(short, long, default_value = "image/*", env = "RCPROXY_MIME")]
    pub mime: Vec<String>,

    // The regex generated from allowed mime types
    #[structopt(skip)]
    pub mime_regex: String,

    /// Log level
    #[structopt(short, long, possible_values = &LogLevel::variants(),
    case_insensitive = true, default_value = "Info", env = "RCPROXY_LOGLEVEL")]
    pub log_level: LogLevel,
}

arg_enum! {
    #[derive(Clone, Copy, Debug)]
    pub enum DefaultFilterRule {
        Allow,
        Deny,
    }
}

arg_enum! {
    #[derive(Clone, Copy, Debug)]
    pub enum LogLevel {
        Trace,
        Debug,
        Info,
        Warn,
        Error,
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(other: LogLevel) -> LevelFilter {
        match other {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

fn split_coma_separated_list(string: &str) -> Vec<String> {
    string.split(',').map(str::trim).map(String::from).collect()
}

fn create_header_map(headers: &[String]) -> Result<HashMap<String, String>, ()> {
    let mut map = HashMap::new();

    for header in headers {
        let parts: Vec<String> = header.split(": ").map(String::from).collect();

        if parts.len() != 2 {
            eprintln!("Error parsing additional header value: \"{}\".", header);
            return Err(());
        }

        let key = parts[0].trim().to_string();
        let value = parts[1].trim().to_string();

        map.insert(key, value);
    }

    Ok(map)
}

fn validate_ip_blacklist(blocks: &[String]) -> bool {
    for block in blocks.iter() {
        if block.parse::<IpNet>().is_err() {
            eprintln!("Error parsing IP range: \"{}\"", block);
            return false;
        }
    }

    true
}

fn validate_and_extract_filters(filters: &[String]) -> Result<(Vec<String>, Vec<String>), ()> {
    let mut filters_allow = Vec::<String>::new();
    let mut filters_deny = Vec::<String>::new();

    for filter in filters.iter() {
        if filter.len() < 3 {
            return Err(());
        }

        match filter.get(..2).unwrap() {
            "a:" => filters_allow.push(filter.get(2..).unwrap().to_string()),
            "d:" => filters_deny.push(filter.get(2..).unwrap().to_string()),
            _ => return Err(()),
        }
    }

    Ok((filters_allow, filters_deny))
}

fn create_mime_regex(mimes: &[String]) -> String {
    mimes.join("|").replace("*", ".+")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_coma_separated_list() {
        let strings = vec!["value1", "127.0.0.0/8, 10.0.0.0/24", "image/*, audio/*"];
        let results: Vec<Vec<String>> = vec![
            vec!["value1".to_string()],
            vec!["127.0.0.0/8".to_string(), "10.0.0.0/24".to_string()],
            vec!["image/*".to_string(), "audio/*".to_string()],
        ];

        for (index, string) in strings.iter().enumerate() {
            assert_eq!(split_coma_separated_list(&string), results[index]);
        }
    }

    #[test]
    fn test_create_mime_regex() {
        let mimes: Vec<String> = vec!["image/*".to_string(), "audio/*".to_string()];
        let mime_regex = "image/.+|audio/.+";

        assert_eq!(create_mime_regex(&mimes), mime_regex);
    }

    #[test]
    fn test_create_header_map() {
        let headers: Vec<String> = vec!["key1: value1".to_string(), "key2: value2".to_string()];

        assert!(create_header_map(&headers).is_ok());

        let headers = create_header_map(&headers).unwrap();

        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("key1"));
        assert!(headers.contains_key("key2"));
        assert_eq!(headers.get("key1"), Some(&"value1".to_string()));
        assert_eq!(headers.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_create_header_map_error() {
        let headers: Vec<String> = vec![
            "key1: value1".to_string(),
            "key2: value2: error".to_string(),
        ];

        assert!(create_header_map(&headers).is_err());
    }

    #[test]
    fn test_validate_ip_blacklist() {
        let blacklist: Vec<String> = vec!["127.0.0.0/8".to_string(), "::1/128".to_string()];

        assert_eq!(validate_ip_blacklist(&blacklist), true)
    }

    #[test]
    fn test_validate_ip_blacklist_error() {
        let blacklist: Vec<String> = vec!["127.0.0.0.1/8".to_string(), "::1/128".to_string()];

        assert_eq!(validate_ip_blacklist(&blacklist), false)
    }

    #[test]
    fn test_validate_and_extract_filters_allow_and_deny() {
        let filters: Vec<String> = vec![
            "a:.*allow.com/.*".to_string(),
            "d:.*deny.com/.*".to_string(),
        ];
        let filters_allow = vec![".*allow.com/.*".to_string()];
        let filters_deny = vec![".*deny.com/.*".to_string()];

        assert_eq!(
            validate_and_extract_filters(&filters),
            Ok((filters_allow, filters_deny))
        );
    }

    #[test]
    fn test_validate_and_extract_filters_allow_only() {
        let filters: Vec<String> = vec![
            "a:.*allow.com/.*".to_string(),
            "a:.*allow2.com/.*".to_string(),
        ];
        let filters_allow = vec![".*allow.com/.*".to_string(), ".*allow2.com/.*".to_string()];
        let filters_deny: Vec<String> = vec![];

        assert_eq!(
            validate_and_extract_filters(&filters),
            Ok((filters_allow, filters_deny))
        );
    }

    #[test]
    fn test_validate_and_extract_filters_deny_only() {
        let filters: Vec<String> = vec![
            "d:.*deny.com/.*".to_string(),
            "d:.*deny2.com/.*".to_string(),
        ];
        let filters_allow: Vec<String> = vec![];
        let filters_deny = vec![".*deny.com/.*".to_string(), ".*deny2.com/.*".to_string()];

        assert_eq!(
            validate_and_extract_filters(&filters),
            Ok((filters_allow, filters_deny))
        );
    }

    #[test]
    fn test_validate_and_extract_filters_error() {
        let filters: Vec<String> = vec!["ad:.*deny.com/.*".to_string()];

        assert_eq!(validate_and_extract_filters(&filters), Err(()));
    }
}
