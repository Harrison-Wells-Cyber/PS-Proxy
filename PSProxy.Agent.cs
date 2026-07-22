using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSProxy.Agent
{
    public sealed class Tunnel
    {
        private readonly string server;
        private readonly int port;
        private readonly string certPin;
        private readonly string enrollToken;
        public Tunnel(string server, int port, string certPin, string enrollToken)
        {
            this.server = server; this.port = port; this.certPin = NormalizeHex(certPin); this.enrollToken = enrollToken;
            if (this.certPin.Length != 64) throw new ArgumentException("CertPin must be a SHA-256 hex string");
            if (String.IsNullOrWhiteSpace(enrollToken)) throw new ArgumentException("EnrollToken is required");
        }
        public void Run()
        {
            Console.Error.WriteLine("[ps-proxy] connecting to {0}:{1}", server, port);
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;
            var req = (HttpWebRequest)WebRequest.Create("https://" + server + ":" + port + "/enroll");
            req.Method = "POST";
            req.Headers["X-PSProxy-Enrollment"] = enrollToken;
            req.ContentLength = 0;
            using (var resp = (HttpWebResponse)req.GetResponse())
            {
                if (resp.StatusCode != HttpStatusCode.OK) throw new Exception("server enrollment failed: " + resp.StatusCode);
            }
            Console.Error.WriteLine("[ps-proxy] enrolled; tunnel protocol not implemented in this release scaffold");
            while (true) System.Threading.Thread.Sleep(60000);
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
        private static void SendLine(Stream s, string line) { var b = Encoding.ASCII.GetBytes(line + "\n"); s.Write(b,0,b.Length); s.Flush(); }
        private static string ReadLine(Stream s) { using (var ms = new MemoryStream()) { int c; while ((c=s.ReadByte())>=0) { if (c=='\n') break; if (c!='\r') ms.WriteByte((byte)c); } return Encoding.ASCII.GetString(ms.ToArray()); } }
        private static string NormalizeHex(string s) { return (s ?? "").Trim().ToLowerInvariant().Replace(":", "").Replace(" ", ""); }
    }
}
