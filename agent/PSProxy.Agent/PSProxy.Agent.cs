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
        private readonly string serverKey;
        private ulong sendSeq;
        private ulong recvSeq;
        private byte[] encKey;
        private byte[] macKey;
        private readonly string enrollToken;
        private readonly string reconnectToken;
        private readonly string dnsTarget;
        private readonly ConcurrentDictionary<ulong, StreamCtx> streams = new ConcurrentDictionary<ulong, StreamCtx>();
        private readonly object sendLock = new object();
        private SslStream tls;
        private volatile bool stopping;

        public Tunnel(string server, int port, string serverKey, string enrollToken, string reconnectToken, string dnsTarget)
        {
            this.server = server;
            this.port = port;
            this.serverKey = serverKey;
            this.enrollToken = enrollToken;
            this.reconnectToken = reconnectToken ?? "";
            this.dnsTarget = dnsTarget ?? "";
            if (String.IsNullOrWhiteSpace(serverKey)) throw new ArgumentException("ServerKey is required");
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
                    WriteAscii("PSP1\n");
                    SecureHandshake();
                    SendFrame(new Frame(0, FramePing, Encoding.ASCII.GetBytes("ENROLL " + enrollToken + " " + reconnectToken)));
                    Frame hello = ReadFrame();
                    if (hello.Type != FramePong || Encoding.ASCII.GetString(hello.Payload) != "OK") throw new Exception("server did not accept enrollment");
                    Console.Error.WriteLine("[ps-proxy] enrolled and ready");
                    ReadLoop();
                }
            }
        }


        private void SecureHandshake()
        {
            byte[] secret = RandomBytes(32);
            byte[] nonce = RandomBytes(32);
            byte[] pubDer = Convert.FromBase64String(serverKey.Trim());
            byte[] encSecret;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(ParseRsaPublicKey(pubDer));
                // .NET Framework RSACryptoServiceProvider supports OAEP only as
                // SHA-1 with the default empty OAEP label. The server accepts
                // this format for PowerShell 5.1 agent compatibility.
                encSecret = rsa.Encrypt(secret, true);
            }
            string hello = "HELLO " + B64Url(encSecret) + " " + B64Url(nonce) + "\n";
            WriteAscii(hello);
            string proofLine = ReadLineAscii();
            string[] parts = proofLine.Trim().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3 || parts[0] != "PROOF") throw new Exception("invalid secure handshake proof");
            byte[] serverNonce = B64UrlDecode(parts[1]);
            byte[] proof = B64UrlDecode(parts[2]);
            byte[] expected;
            using (var h = new HMACSHA256(secret))
            {
                expected = h.ComputeHash(Concat(Concat(Concat(Concat(Encoding.ASCII.GetBytes("PSP1\n"), Encoding.ASCII.GetBytes(hello)), serverNonce), nonce), pubDer));
            }
            if (!ConstantTimeEquals(proof, expected)) throw new Exception("secure handshake proof mismatch");
            using (var sha = SHA256.Create())
            {
                encKey = sha.ComputeHash(Concat(secret, Encoding.ASCII.GetBytes("psproxy aes-cbc")));
                macKey = sha.ComputeHash(Concat(secret, Encoding.ASCII.GetBytes("psproxy hmac")));
            }
            sendSeq = 0; recvSeq = 0;
        }

        private string ReadLineAscii()
        {
            var ms = new MemoryStream();
            while (true)
            {
                int b = tls.ReadByte();
                if (b < 0) throw new EndOfStreamException();
                ms.WriteByte((byte)b);
                if (b == '\n') return Encoding.ASCII.GetString(ms.ToArray());
                if (ms.Length > 8192) throw new IOException("line too long");
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
            byte[] plainFrame = EncodePlainFrame(f);
            byte[] seq = U64BE(sendSeq);
            byte[] plain = Concat(seq, plainFrame);
            byte[] padded = Pkcs7Pad(plain, 16);
            byte[] iv = RandomBytes(16);
            byte[] ct;
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None; aes.Key = encKey; aes.IV = iv;
                using (var enc = aes.CreateEncryptor()) { ct = enc.TransformFinalBlock(padded, 0, padded.Length); }
            }
            byte[] body = Concat(iv, ct);
            byte[] tag;
            using (var h = new HMACSHA256(macKey)) { tag = h.ComputeHash(Concat(seq, body)); }
            byte[] rec = Concat(body, tag);
            byte[] len = new byte[4]; WriteI32BE(len, 0, rec.Length);
            lock (sendLock)
            {
                tls.Write(len, 0, len.Length); tls.Write(rec, 0, rec.Length); tls.Flush();
                sendSeq++;
            }
        }

        private Frame ReadFrame()
        {
            int len = ReadI32BE(ReadExact(4), 0);
            if (len < 48 || len > MaxPayload + 1024) throw new IOException("invalid secure record length: " + len);
            byte[] rec = ReadExact(len);
            byte[] body = Slice(rec, 0, len - 32);
            byte[] tag = Slice(rec, len - 32, 32);
            byte[] seq = U64BE(recvSeq);
            byte[] expected;
            using (var h = new HMACSHA256(macKey)) { expected = h.ComputeHash(Concat(seq, body)); }
            if (!ConstantTimeEquals(tag, expected)) throw new IOException("secure frame authentication failed");
            byte[] iv = Slice(body, 0, 16); byte[] ct = Slice(body, 16, body.Length - 16); byte[] pt;
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None; aes.Key = encKey; aes.IV = iv;
                using (var dec = aes.CreateDecryptor()) { pt = dec.TransformFinalBlock(ct, 0, ct.Length); }
            }
            pt = Pkcs7Unpad(pt, 16);
            ulong gotSeq = ReadU64BE(pt, 0);
            if (gotSeq != recvSeq) throw new IOException("secure frame sequence mismatch");
            recvSeq++;
            return DecodePlainFrame(Slice(pt, 8, pt.Length - 8));
        }

        private byte[] EncodePlainFrame(Frame f)
        {
            byte[] b = new byte[13 + f.Payload.Length];
            WriteU64BE(b, 0, f.StreamID); b[8] = f.Type; WriteI32BE(b, 9, f.Payload.Length);
            Buffer.BlockCopy(f.Payload, 0, b, 13, f.Payload.Length); return b;
        }

        private Frame DecodePlainFrame(byte[] b)
        {
            if (b.Length < 13) throw new IOException("frame too short");
            int len = ReadI32BE(b, 9); if (len < 0 || len > MaxPayload || b.Length != 13 + len) throw new IOException("invalid frame length");
            return new Frame(ReadU64BE(b, 0), b[8], Slice(b, 13, len));
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
            // TLS is transport/staging only. PS-Proxy server identity is verified by SecureHandshake.
            return true;
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


        private static byte[] RandomBytes(int n) { byte[] b = new byte[n]; using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(b); } return b; }
        private static byte[] Concat(byte[] a, byte[] b) { byte[] o = new byte[a.Length + b.Length]; Buffer.BlockCopy(a,0,o,0,a.Length); Buffer.BlockCopy(b,0,o,a.Length,b.Length); return o; }
        private static byte[] Slice(byte[] b, int o, int n) { byte[] r = new byte[n]; Buffer.BlockCopy(b,o,r,0,n); return r; }
        private static byte[] U64BE(ulong v) { byte[] b = new byte[8]; WriteU64BE(b,0,v); return b; }
        private static string B64Url(byte[] b) { return Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_'); }
        private static byte[] B64UrlDecode(string s) { string t = s.Replace('-','+').Replace('_','/'); while (t.Length % 4 != 0) t += "="; return Convert.FromBase64String(t); }
        private static bool ConstantTimeEquals(byte[] a, byte[] b) { if (a == null || b == null || a.Length != b.Length) return false; int d = 0; for (int i=0;i<a.Length;i++) d |= a[i]^b[i]; return d == 0; }
        private static byte[] Pkcs7Pad(byte[] b, int block) { int pad = block - (b.Length % block); byte[] o = new byte[b.Length + pad]; Buffer.BlockCopy(b,0,o,0,b.Length); for (int i=b.Length;i<o.Length;i++) o[i]=(byte)pad; return o; }
        private static byte[] Pkcs7Unpad(byte[] b, int block) { if (b.Length == 0 || b.Length % block != 0) throw new IOException("invalid padding"); int p = b[b.Length-1]; if (p < 1 || p > block || p > b.Length) throw new IOException("invalid padding"); for (int i=b.Length-p;i<b.Length;i++) if (b[i] != p) throw new IOException("invalid padding"); return Slice(b,0,b.Length-p); }
        private static RSAParameters ParseRsaPublicKey(byte[] spki)
        {
            int o = 0;
            int spkiEnd = BeginTLV(spki, ref o, 0x30);
            int algEnd = BeginTLV(spki, ref o, 0x30);
            o = algEnd;
            byte[] bit = ReadTLV(spki, ref o, 0x03);
            if (o != spkiEnd || bit.Length < 1 || bit[0] != 0) throw new CryptographicException("invalid public key");
            o = 1;
            int rsaEnd = BeginTLV(bit, ref o, 0x30);
            byte[] mod = ReadTLV(bit, ref o, 0x02);
            byte[] exp = ReadTLV(bit, ref o, 0x02);
            if (o != rsaEnd) throw new CryptographicException("invalid public key");
            if (mod.Length > 1 && mod[0] == 0) mod = Slice(mod, 1, mod.Length - 1);
            return new RSAParameters { Modulus = mod, Exponent = exp };
        }
        private static int BeginTLV(byte[] b, ref int o, int tag) { if (o >= b.Length || b[o++] != tag) throw new CryptographicException("asn1 tag"); int len = ReadLen(b, ref o); if (len < 0 || o + len > b.Length) throw new CryptographicException("asn1 len"); int end = o + len; return end; }
        private static byte[] ReadTLV(byte[] b, ref int o, int tag) { int end = BeginTLV(b, ref o, tag); byte[] v = Slice(b, o, end - o); o = end; return v; }
        private static int ReadLen(byte[] b, ref int o) { if (o >= b.Length) throw new CryptographicException("asn1 len"); int v = b[o++]; if ((v & 0x80) == 0) return v; int n = v & 0x7f; if (n < 1 || n > 4 || o + n > b.Length) throw new CryptographicException("asn1 len"); int len = 0; for (int i = 0; i < n; i++) len = (len << 8) | b[o++]; return len; }
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
