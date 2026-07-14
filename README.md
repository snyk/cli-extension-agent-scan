<p align="center">
  <img src="https://snyk.io/style/asset/logo/snyk-print.svg" />
</p>

# Snyk MCP Scan CLI Extension

## Overview

This module implements the Snyk CLI Extension to scan your MCP tools.


## Local development

This extension is compiled into the Snyk CLI and, at runtime, downloads the
[`agent-scan`](https://github.com/snyk/agent-scan) binary from GitHub Releases and
verifies its SHA-256 checksum before running it. To develop against local changes in
both this extension and the `agent-scan` binary, wire the pieces together as follows.

### Prerequisites

- The repositories checked out as siblings, because the CLI's `replace` directive
  resolves this extension via a relative path (`../../cli-extension-agent-scan`):

  ```text
  <workspace>/
  ├── cli/                        # github.com/snyk/cli
  ├── cli-extension-agent-scan/   # this repo
  └── agent-scan/                 # github.com/snyk/agent-scan
  ```

### 1. Build a local `agent-scan` binary

From the `agent-scan` repo, build the standalone binary (output: `dist/agent-scan`):

```bash
cd ../agent-scan
make binary
```

### 2. Point the Snyk CLI at your local extension

Clone [`snyk/cli`](https://github.com/snyk/cli) as a sibling directory, then in
`cliv2/go.mod` uncomment the local `replace` directive so the CLI builds against your
working copy instead of a published version:

```go
replace github.com/snyk/cli-extension-agent-scan => ../../cli-extension-agent-scan
```

Then sync and build the CLI:

```bash
cd ../cli/
make clean
make build
```

The last line should be something like:
`-- Installing ( <Some-path>/cli/binary-releases/snyk-macos-arm64 )`

This is the built Snyk CLI binary.

### 3. Point the extension at your local `agent-scan` binary

Set `SNYK_AGENT_SCAN_BINARY_PATH` to the binary from step 1. When set, the extension
uses that binary directly and **skips the download, cache, and checksum verification**.
This is for local development only and must never be relied on in production.

```bash
export SNYK_AGENT_SCAN_BINARY_PATH="$(pwd)/../../agent-scan/dist/agent-scan"
```

### 4. Run

Invoke the locally built CLI binary produced by step 2 (the exact path is
platform-specific, e.g. `cliv2/bin/snyk_darwin_arm64`).

```bash
<Some-path>/cli/binary-releases/snyk-macos-arm64 agent-scan --experimental
```

To return to the normal download-and-verify behavior, `unset SNYK_AGENT_SCAN_BINARY_PATH`.


## Contributing

This repository is closed to public contributions.