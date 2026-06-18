## 1. Callback listener

- [x] 1.1 Implement embedded HTTP listener on random loopback port with `/callback` endpoint
- [x] 1.2 Inject callback URL into tool call probe args alongside internal targets
- [x] 1.3 Record CRITICAL finding when callback receives GET request, identifying source server/tool
- [x] 1.4 Shutdown listener after probe phase with 30s grace period
- [x] 1.5 Add `--callback-port` flag for fixed port (default: random)

## 2. Expanded cloud targets

- [x] 2.1 Add Azure metadata endpoint with `Metadata: true` header requirement
- [x] 2.2 Add DigitalOcean metadata endpoint
- [x] 2.3 Add Oracle Cloud metadata endpoint
- [x] 2.4 Gate new targets behind extended/full probe depth

## 3. HTTP method and header probes

- [x] 3.1 Add POST/PUT probe variants for each internal target
- [x] 3.2 Add `X-Forwarded-Host`, `Host`, `Referer` header injection variants
- [x] 3.3 Gate behind extended/full probe depth

## 4. Redirect chain following

- [x] 4.1 Replace `http.ErrUseLastResponse` with custom redirect handler allowing up to 5 hops
- [x] 4.2 Check each redirect URL for internal IP before following
- [x] 4.3 Report internal redirect at any hop with hop number in finding

## 5. DNS rebinding

- [x] 5.1 Add DNS rebinding hostname to full-depth target list
- [x] 5.2 Detect resolution to internal IP after redirect from rebinding host
- [x] 5.3 Document external service dependency

## 6. Probe depth and targets file

- [x] 6.1 Add `--probe-depth` flag with basic/extended/full values
- [x] 6.2 Gate all new probe techniques behind appropriate depth levels
- [x] 6.3 Add `--targets-file` flag to load probe targets from file (one URL per line)

## 7. Tests

- [x] 7.1 Test callback listener with mock server that connects to callback URL
- [x] 7.2 Test redirect chain following with multi-hop mock server
- [x] 7.3 Test probe depth: basic only does GET, extended adds methods/headers, full adds callback
- [x] 7.4 Test DNS rebinding probe against mock rebinding endpoint
