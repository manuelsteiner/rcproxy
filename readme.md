# rcproxy
rcproxy is a content proxy to securely serve HTTP assets via HTTPS. It is implemented in Rust and heavily inspired by [camo]() and [go-camo]().

# Features
- Supports Base64 and HEX encoded URLs
- Enable or disable proxying of HTTPS assets
- Allows setting MIME types that are allowed to be proxied
- Allows source IP blacklists (from which no requests will be processed)
- Supports for target regexp white- and blacklists (to control which content is being proxied)
- Allows setting additional response headers
- Source content can be restricted in file size (only assets up to the maximum file size are proxied)
- Allows restrictions of maximum redirects while fetching sources
- A maximum timeout for fetching content can be set
- Usage of a proxy (additionally with username and password authentication) is supported for fetching content

# TODOs, Nice to Haves
- Evaluate different HTTP client and server frameworks in Rust. Maybe switch from Gotham.
- Support streaming for larger content
- Support SSL connections natively (without the need of a reverse proxy)
- Implement caching
- Environment variable support for additional headers (currently only supported as command line arguments)
- Encapsulate server config as well as the client struct somehow, in order to get rid of static elements (and lazy static). Tricky because the client needs to be used in the HTTP handlers of the web framework and server configs need to be used in multiple places
- Add if !cfg!(test) to exclude headers and ip blacklists evaluation from command line argument if running in test environment? Would allow referencing static map and vector in testing without having a separate variable in the test setup