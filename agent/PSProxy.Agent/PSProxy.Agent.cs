using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace PSProxy.Agent
{
    public sealed class Tunnel
    {
        private const byte FrameOpen = 1, FrameOpenOK = 2, FrameOpenFail = 3, FrameData = 4, FrameClose = 5, FramePing = 6, FramePong = 7, FrameDNSQuery = 8, FrameDNSReply = 9;
        private const int MaxPayload = 1 << 20;
        private readonly string server;
        private readonly int port;
        private readonly string certPin;
        private readonly string enrollToken;
        private readonly string reconnectToken;
        private readonly string dnsTarget;
        private readonly ConcurrentDictionary<ulong, StreamCtx> streams = new ConcurrentDictionary<ulong, StreamCtx>();
        private readonly object sendLock = new object();
        private SslStream tls;
        private volatile bool stopping;

        public Tunnel(string server, int port, string certPin, string enrollToken, string reconnectToken, string dnsTarget)
        {
            this.server = server;
            this.port = port;
            this.certPin = NormalizeHex(certPin);
            this.enrollToken = enrollToken;
            this.reconnectToken = reconnectToken ?? "";
            this.dnsTarget = dnsTarget ?? "";
            if (this.certPin.Length != 64) throw new ArgumentException("CertPin must be a SHA-256 hex string");
            if (String.IsNullOrWhiteSpace(enrollToken)) throw new ArgumentException("EnrollToken is required");
        }

        public void Run()
        {
            int delayMs = 1000;
            while (!stopping)
            {
                try
                {
                    RunOnce();
                    delayMs = 1000;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[ps-proxy] tunnel error: {0}", ex.Message);
                    CloseAllStreams();
                    if (stopping) break;
                    Thread.Sleep(delayMs);
                    delayMs = Math.Min(delayMs * 2, 30000);
                }
            }
        }

        private void RunOnce()
        {
            Console.Error.WriteLine("[ps-proxy] connecting to {0}:{1}", server, port);
            using (var tcp = new TcpClient())
            {
                tcp.NoDelay = true;
                ConnectWithTimeout(tcp, server, port, 15000);
                using (tls = new SslStream(tcp.GetStream(), false, ValidateServerCertificate))
                {
                    tls.AuthenticateAsClient(server, null, SslProtocols.Tls12, false);
                    WriteAscii("PSP1\nENROLL " + enrollToken + " " + reconnectToken + "\n");
                    Frame hello = ReadFrame();
                    if (hello.Type != FramePong || Encoding.ASCII.GetString(hello.Payload) != "OK") throw new Exception("server did not accept enrollment");
                    Console.Error.WriteLine("[ps-proxy] enrolled and ready");
                    ReadLoop();
                }
            }
        }

        private void ReadLoop()
        {
            while (!stopping)
            {
                Frame f = ReadFrame();
                switch (f.Type)
                {
                    case FrameOpen: HandleOpen(f.StreamID, Encoding.UTF8.GetString(f.Payload)); break;
                    case FrameData: HandleData(f.StreamID, f.Payload); break;
                    case FrameClose: CloseStream(f.StreamID, false); break;
                    case FramePing: SendFrame(new Frame(f.StreamID, FramePong, new byte[0])); break;
                    case FrameDNSQuery: StartDnsQuery(f.StreamID, f.Payload); break;
                }
            }
        }

        private void HandleOpen(ulong sid, string target)
        {
            try
            {
                string host; int dstPort; SplitTarget(target, out host, out dstPort);
                var client = new TcpClient();
                client.NoDelay = true;
                ConnectWithTimeout(client, host, dstPort, 15000);
                var ctx = new StreamCtx(sid, client);
                if (!streams.TryAdd(sid, ctx)) { client.Close(); throw new Exception("duplicate stream"); }
                SendFrame(new Frame(sid, FrameOpenOK, new byte[0]));
                var t = new Thread(delegate() { PumpTargetToServer(ctx); });
                t.IsBackground = true;
                t.Start();
            }
            catch (Exception ex)
            {
                SendFrame(new Frame(sid, FrameOpenFail, Encoding.UTF8.GetBytes(ex.Message)));
            }
        }

        private void HandleData(ulong sid, byte[] payload)
        {
            StreamCtx ctx;
            if (!streams.TryGetValue(sid, out ctx)) { SendFrame(new Frame(sid, FrameClose, new byte[0])); return; }
            try { ctx.Stream.Write(payload, 0, payload.Length); }
            catch { CloseStream(sid, true); }
        }

        private void StartDnsQuery(ulong sid, byte[] payload)
        {
            var t = new Thread(delegate() { HandleDnsQuery(sid, payload); });
            t.IsBackground = true;
            t.Start();
        }

        private void HandleDnsQuery(ulong sid, byte[] payload)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(dnsTarget)) throw new Exception("DNS target is not configured");
                string host; int dstPort; SplitTarget(dnsTarget, out host, out dstPort);
                using (var udp = new UdpClient())
                {
                    udp.Client.ReceiveTimeout = 5000;
                    udp.Connect(host, dstPort);
                    udp.Send(payload, payload.Length);
                    IPEndPoint ep = null;
                    byte[] resp = udp.Receive(ref ep);
                    SendFrame(new Frame(sid, FrameDNSReply, resp));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[ps-proxy] DNS query failed: " + ex.Message);
                SendFrame(new Frame(sid, FrameDNSReply, new byte[0]));
            }
        }

        private void PumpTargetToServer(StreamCtx ctx)
        {
            byte[] buf = new byte[32768];
            try
            {
                while (!stopping)
                {
                    int n = ctx.Stream.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    byte[] payload = new byte[n];
                    Buffer.BlockCopy(buf, 0, payload, 0, n);
                    SendFrame(new Frame(ctx.StreamID, FrameData, payload));
                }
            }
            catch { }
            finally { CloseStream(ctx.StreamID, true); }
        }

        private void CloseStream(ulong sid, bool notify)
        {
            StreamCtx ctx;
            if (streams.TryRemove(sid, out ctx))
            {
                try { ctx.Client.Close(); } catch { }
                if (notify) { try { SendFrame(new Frame(sid, FrameClose, new byte[0])); } catch { } }
            }
        }

        private void CloseAllStreams()
        {
            foreach (ulong sid in streams.Keys) CloseStream(sid, false);
        }

        private void SendFrame(Frame f)
        {
            if (f.Payload == null) f.Payload = new byte[0];
            if (f.Payload.Length > MaxPayload) throw new InvalidOperationException("frame payload too large");
            byte[] hdr = new byte[13];
            WriteU64BE(hdr, 0, f.StreamID);
            hdr[8] = f.Type;
            WriteI32BE(hdr, 9, f.Payload.Length);
            lock (sendLock)
            {
                tls.Write(hdr, 0, hdr.Length);
                if (f.Payload.Length > 0) tls.Write(f.Payload, 0, f.Payload.Length);
                tls.Flush();
            }
        }

        private Frame ReadFrame()
        {
            byte[] hdr = ReadExact(13);
            ulong sid = ReadU64BE(hdr, 0);
            byte typ = hdr[8];
            int len = ReadI32BE(hdr, 9);
            if (len < 0 || len > MaxPayload) throw new IOException("frame payload too large: " + len);
            return new Frame(sid, typ, len == 0 ? new byte[0] : ReadExact(len));
        }

        private byte[] ReadExact(int n)
        {
            byte[] b = new byte[n];
            int off = 0;
            while (off < n)
            {
                int got = tls.Read(b, off, n - off);
                if (got <= 0) throw new EndOfStreamException();
                off += got;
            }
            return b;
        }

        private void WriteAscii(string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            tls.Write(b, 0, b.Length);
            tls.Flush();
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var cert2 = new X509Certificate2(certificate);
            using (var sha = SHA256.Create())
            {
                string got = BitConverter.ToString(sha.ComputeHash(cert2.RawData)).Replace("-", "").ToLowerInvariant();
                if (got != certPin) { Console.Error.WriteLine("[ps-proxy] cert pin mismatch: " + got); return false; }
            }
            return sslPolicyErrors == SslPolicyErrors.None;
        }

        private static void SplitTarget(string target, out string host, out int dstPort)
        {
            int idx = target.LastIndexOf(':');
            if (idx <= 0 || idx == target.Length - 1) throw new ArgumentException("target must be host:port");
            host = target.Substring(0, idx);
            dstPort = Int32.Parse(target.Substring(idx + 1));
            if (dstPort < 1 || dstPort > 65535) throw new ArgumentException("invalid port");
        }

        private static void ConnectWithTimeout(TcpClient client, string host, int dstPort, int timeoutMs)
        {
            IAsyncResult ar = client.BeginConnect(host, dstPort, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                try { client.Close(); } catch { }
                throw new TimeoutException("connect timed out: " + host + ":" + dstPort);
            }
            client.EndConnect(ar);
        }

        private static string NormalizeHex(string s) { return (s ?? "").Trim().ToLowerInvariant().Replace(":", "").Replace(" ", ""); }
        private static void WriteI32BE(byte[] b, int o, int v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        private static int ReadI32BE(byte[] b, int o) { return ((int)b[o] << 24) | ((int)b[o + 1] << 16) | ((int)b[o + 2] << 8) | (int)b[o + 3]; }
        private static void WriteU64BE(byte[] b, int o, ulong v) { for (int i = 7; i >= 0; i--) { b[o + i] = (byte)v; v >>= 8; } }
        private static ulong ReadU64BE(byte[] b, int o) { ulong v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | b[o + i]; return v; }
    }

    public sealed class StreamCtx
    {
        public readonly ulong StreamID;
        public readonly TcpClient Client;
        public readonly NetworkStream Stream;
        public StreamCtx(ulong streamID, TcpClient client) { StreamID = streamID; Client = client; Stream = client.GetStream(); }
    }

    public struct Frame
    {
        public ulong StreamID;
        public byte Type;
        public byte[] Payload;
        public Frame(ulong streamID, byte type, byte[] payload) { StreamID = streamID; Type = type; Payload = payload; }
    }
}
