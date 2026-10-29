# Changelog

## [0.2.0](https://github.com/divmora/authpin/compare/v0.1.0...v0.2.0) (2026-10-29)


### Features

* add /readyz readiness probe, /livez liveness probe, and Prometheus /metrics ([a1cdd55](https://github.com/divmora/authpin/commit/a1cdd5511b2934c0d2789619c5dfe30c706dc299))
* add support for dynamic otp_length and otp_type (numeric | alphanumeric) ([277908a](https://github.com/divmora/authpin/commit/277908aa2b331a81b5ac05ec59c148c9546f4a24))
* complete MySQL and AWS DynamoDB storage engines, add resend & revoke endpoints ([a558c91](https://github.com/divmora/authpin/commit/a558c91b3b496818feadc7aa43f629d375c87529))
* initial release of AuthPin standalone OTP engine ([b75e857](https://github.com/divmora/authpin/commit/b75e857f2fab87a149328511d5f6c84495782666))
* return otp_length & otp_type in generate response, persist in db, and add early length validation ([48dbad0](https://github.com/divmora/authpin/commit/48dbad0a76238eecf0973da147e891fdf40f5546))
* support simultaneous multi-channel OTP dispatch (e.g. Email + SMS together) ([42983d3](https://github.com/divmora/authpin/commit/42983d3dc8c66c5fee6bb24096371f6df484e8e8))


### Bug Fixes

* **lint:** handle unchecked error returns in defer calls for errcheck ([81a52d0](https://github.com/divmora/authpin/commit/81a52d03b7b1a2da39318472f818bc0d2f1ddbdd))
