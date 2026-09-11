// The client is its own module so that adopting egress costs a caller the
// contract and nothing else. Requiring the parent would drag the KMS client,
// the provider dialects and the key library into a process whose whole point is
// that it holds no key — and, measured on visor, an unrelated authz upgrade
// that broke its build.
module github.com/hanzoai/egress/spend

go 1.26.8

require (
	github.com/valyala/fasthttp v1.71.0
	github.com/zap-proto/http v0.3.9
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/zap-proto/go v1.1.0 // indirect
)
