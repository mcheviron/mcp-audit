## 1. Response scoring

- [x] 1.1 Implement `scoreResponse(body string) float64` — keyword frequency weighted by response size
- [x] 1.2 Define keyword list with weights: critical (access_key, token, password), high (secret, credential, private), medium (admin, config, internal)
- [x] 1.3 Gate deep regex analysis behind score threshold (>0.7)

## 2. Entropy analysis

- [x] 2.1 Implement Shannon entropy calculation on response body
- [x] 2.2 Classify entropy bands: high (>7.5 encrypted), medium (3.0-7.5 text), low (<3.0 structured), very low (<1.5 suspicious)
- [x] 2.3 Combine entropy with keyword score for findings

## 3. Response classification

- [x] 3.1 Implement `classifyResponse(body, contentType string) ResponseClass` — returns metadata, error, data, or binary
- [x] 3.2 Route to appropriate analysis path based on classification
- [x] 3.3 Classify by content-type header first, body characteristics second

## 4. Timing analysis

- [x] 4.1 Record `time.Duration` per probe in `probeResult`
- [x] 4.2 Compute mean and stddev across all probes for a server
- [x] 4.3 Flag responses >2 stddev faster than mean as INFO

## 5. Response limit

- [x] 5.1 Add `--max-response` flag (default 65536)
- [x] 5.2 Replace hardcoded 4096 limit in `dynamic.go:97` and `transport.go:110` with configurable value
- [x] 5.3 Enforce maximum of 1MB to prevent memory exhaustion

## 6. Tests

- [x] 6.1 Test response scoring with known-clean and known-suspicious responses
- [x] 6.2 Test entropy calculation against plaintext, JSON, and base64 inputs
- [x] 6.3 Test response classification for each class
- [x] 6.4 Test timing analysis with varied response delays
- [x] 6.5 Test `--max-response` truncation at boundary values
