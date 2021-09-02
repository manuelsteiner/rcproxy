use gotham::hyper::body::Bytes;
use log::debug;
use mime::Mime;
use regex::Regex;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::redirect::Policy;
use reqwest::{Client, Response, StatusCode};
use std::time::Duration;

pub struct HttpClient<'a> {
    client: Client,
    max_size: u32,
    allowed_mime_regex: &'a str,
}

impl<'a> HttpClient<'a> {
    pub fn new(
        max_redirects: u8,
        timeout: u8,
        max_size: u32,
        allowed_mime_regex: &'a str,
        proxy: &Option<String>,
        proxy_username: &Option<String>,
        proxy_password: &Option<String>,
    ) -> Result<HttpClient<'a>, ()> {
        let mut client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(timeout.into()))
            .redirect(Policy::limited(max_redirects.into()));

        if let Some(proxy) = proxy {
            debug!("Setting client HTTP proxy to {}.", proxy);

            let mut proxy = match reqwest::Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(_error) => {
                    debug!("Error building HTTP client proxy.");
                    return Err(());
                }
            };

            if let (Some(username), Some(password)) = (proxy_username, proxy_password) {
                debug!(
                    "Setting client HTTP proxy username to {} and password to {}.",
                    username, password
                );

                proxy = proxy.basic_auth(username, password);
            }

            client = client.proxy(proxy);
        }

        let client = match client.build() {
            Ok(client) => client,
            Err(_error) => {
                debug!("Error building HTTP client.");
                return Err(());
            }
        };

        let http_client = HttpClient {
            client,
            max_size,
            allowed_mime_regex,
        };

        Ok(http_client)
    }

    pub async fn get(&self, url: &str) -> Result<(Mime, Bytes), StatusCode> {
        let request = match self.client.get(url).build() {
            Ok(request) => request,
            Err(_error) => {
                debug!("Error building HTTP request.");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let content_response = match self.client.execute(request).await {
            Ok(response) => response,
            Err(_error) => {
                debug!("Error fetching URL {}.", url);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        match content_response.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => {
                debug!("Requested URL {} returned NOT FOUND status code.", url);
                return Err(StatusCode::NOT_FOUND);
            }
            _ => {
                debug!("Requested URL {} returned non OK status code.", url);
                return Err(StatusCode::NOT_FOUND);
            }
        };

        debug!("Extracting content MIME of URL {}.", url);

        let content_type = match HttpClient::extract_mime(url, &content_response) {
            Ok(content_type) => content_type,
            Err(()) => {
                debug!("Error getting content MIME of URL {}.", url);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        debug!("Checking if source MIME {} is allowed.", content_type);

        if !self.validate_mime(content_type) {
            debug!("MIME {} is not allowed.", content_type);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        debug!("Parsing content MIME {} of URL {}.", content_type, url);

        let mime = match content_type.parse() {
            Ok(mime) => mime,
            Err(_error) => {
                debug!("Error parsing content MIME of URL {}.", url);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        if self.max_size > 0 {
            debug!("Extracting content length of URL {}.", url);

            let content_length = match HttpClient::extract_content_length(url, &content_response) {
                Ok(content_length) => content_length,
                Err(()) => {
                    debug!("Error getting content length of URL {}.", url);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };

            if content_length > self.max_size {
                debug!(
                    "Content length of URL {} exceeds the maximum allowed value of {} bytes.",
                    url,
                    self.max_size.to_string()
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        debug!("Getting content body of URL {}.", url);

        let content = match content_response.bytes().await {
            Ok(content) => content,
            Err(_error) => {
                debug!("Error fetching content body of URL {}.", url);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        Ok((mime, content))
    }

    fn extract_mime<'b>(url: &str, content_response: &'b Response) -> Result<&'b str, ()> {
        let content_type_header = match content_response.headers().get(CONTENT_TYPE) {
            Some(header) => header,
            None => {
                debug!("Content type header is not set in response (URL: {}).", url);
                return Err(());
            }
        };

        let content_type = match content_type_header.to_str() {
            Ok(content_type) => content_type,
            Err(_error) => {
                debug!("Error parsing content type for URL {}.", url);
                return Err(());
            }
        };

        Ok(content_type)
    }

    fn extract_content_length(url: &str, content_response: &Response) -> Result<u32, ()> {
        let content_length_header = match content_response.headers().get(CONTENT_LENGTH) {
            Some(header) => header,
            None => {
                debug!(
                    "Content length header is not set in response (URL: {}).",
                    url
                );
                return Err(());
            }
        };

        let content_length = match content_length_header.to_str() {
            Ok(content_length) => content_length,
            Err(_error) => {
                debug!("Error parsing content length for URL {}.", url);
                return Err(());
            }
        };

        let content_length = match content_length.parse::<u32>() {
            Ok(content_length) => content_length,
            Err(_error) => {
                debug!("Error parsing content length as number for URL {}.", url);
                return Err(());
            }
        };

        Ok(content_length)
    }

    fn validate_mime(&self, content_mime: &str) -> bool {
        let regex = match Regex::new(self.allowed_mime_regex) {
            Ok(regex) => regex,
            Err(_error) => {
                debug!("Discovered invalid regex during parsing.");
                return false;
            }
        };

        regex.is_match(content_mime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_client(mime_regex: &str) -> HttpClient {
        HttpClient::new(0, 4, 0, mime_regex, &None, &None, &None).unwrap()
    }

    #[test]
    fn test_validate_mime_concrete_type() {
        let mime_regex = "image/png|audio/mpeg";
        let content_mimes = vec!["image/png", "audio/mpeg"];

        let client = mock_client(mime_regex);

        for content_mime in content_mimes {
            assert_eq!(client.validate_mime(content_mime), true);
        }
    }

    #[test]
    fn test_validate_mime_sub_type() {
        let mime_regex = "image/.+|audio/.+";
        let content_mimes = vec!["image/png", "audio/mpeg"];

        let client = mock_client(mime_regex);

        for content_mime in content_mimes {
            assert_eq!(client.validate_mime(content_mime), true);
        }
    }

    #[test]
    fn test_validate_mime_invalid_exact_type() {
        let mime_regex = "image/png|audio/mpeg";
        let content_mimes = vec!["image/jpeg", "audio/aac"];

        let client = mock_client(mime_regex);

        for content_mime in content_mimes {
            assert_eq!(client.validate_mime(content_mime), false);
        }
    }

    #[test]
    fn test_validate_mime_invalid_sub_type() {
        let mime_regex = "image/.+|audio/.+";
        let content_mimes = vec!["application/json", "text/plain"];

        let client = mock_client(mime_regex);

        for content_mime in content_mimes {
            assert_eq!(client.validate_mime(content_mime), false);
        }
    }
}
