// Packet Inspector - Windows capture helper.
//
// Captures IP traffic using the raw-socket facility built into Windows
// (SIO_RCVALL), so no driver needs to be installed. Windows only allows this
// for administrators, so the app starts this helper elevated (one UAC prompt
// per capture) and the helper streams a pcap (LINKTYPE_RAW) back to the app
// over a loopback TCP connection.
//
// Usage: pi-capture.exe <port> <token> <ip>[,<ip>...]
// Protocol on the connection:
//   helper -> app: "PIH1 <token>\n"
//   helper -> app: "OK\n" followed by a pcap stream, or "ERR <message>\n"
// The helper exits when the app closes the connection.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

static class Program
{
    static readonly object WriteLock = new object();
    static NetworkStream net;
    static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    static int Main(string[] args)
    {
        if (args.Length < 3) return 2;
        int port = int.Parse(args[0]);
        string token = args[1];
        string[] addresses = args[2].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

        TcpClient client = new TcpClient();
        try { client.Connect(IPAddress.Loopback, port); }
        catch { return 3; }
        client.NoDelay = true;
        net = client.GetStream();
        Send("PIH1 " + token + "\n");

        List<Socket> sockets = new List<Socket>();
        List<string> failures = new List<string>();
        foreach (string a in addresses)
        {
            try { sockets.Add(Open(IPAddress.Parse(a))); }
            catch (Exception e) { failures.Add(a + ": " + e.Message); }
        }
        if (sockets.Count == 0)
        {
            Send("ERR Could not start capture (" + string.Join("; ", failures.ToArray()) + ")\n");
            return 1;
        }
        Send("OK\n");

        // pcap global header: microsecond timestamps, LINKTYPE_RAW (101).
        byte[] hdr = new byte[24];
        PutU32(hdr, 0, 0xa1b2c3d4);
        PutU16(hdr, 4, 2);
        PutU16(hdr, 6, 4);
        PutU32(hdr, 16, 65535);
        PutU32(hdr, 20, 101);
        Write(hdr, hdr.Length);

        foreach (Socket s in sockets)
        {
            Socket sock = s;
            Thread t = new Thread(() => Pump(sock));
            t.IsBackground = true;
            t.Start();
        }

        // The app closes the connection to stop the capture.
        try
        {
            byte[] tmp = new byte[64];
            while (net.Read(tmp, 0, tmp.Length) > 0) { }
        }
        catch { }
        return 0;
    }

    static Socket Open(IPAddress ip)
    {
        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        Socket s = new Socket(ip.AddressFamily, SocketType.Raw, v6 ? ProtocolType.IPv6 : ProtocolType.IP);
        s.ReceiveBufferSize = 8 * 1024 * 1024;
        s.Bind(new IPEndPoint(ip, 0));
        if (!v6) s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        s.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), new byte[4]);
        return s;
    }

    static void Pump(Socket s)
    {
        int expectVersion = s.AddressFamily == AddressFamily.InterNetworkV6 ? 6 : 4;
        byte[] buf = new byte[65536 + 16];
        while (true)
        {
            int n;
            try { n = s.Receive(buf, 16, 65536, SocketFlags.None); }
            catch { Environment.Exit(0); return; }
            if (n <= 0 || (buf[16] >> 4) != expectVersion) continue;
            long micros = (DateTime.UtcNow - Epoch).Ticks / 10;
            PutU32(buf, 0, (uint)(micros / 1000000));
            PutU32(buf, 4, (uint)(micros % 1000000));
            PutU32(buf, 8, (uint)n);
            PutU32(buf, 12, (uint)n);
            Write(buf, 16 + n);
        }
    }

    static void Send(string line)
    {
        byte[] b = Encoding.ASCII.GetBytes(line);
        Write(b, b.Length);
    }

    static void Write(byte[] b, int len)
    {
        lock (WriteLock)
        {
            try { net.Write(b, 0, len); }
            catch { Environment.Exit(0); }
        }
    }

    static void PutU32(byte[] b, int o, uint v)
    {
        b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
    }

    static void PutU16(byte[] b, int o, int v)
    {
        b[o] = (byte)v; b[o + 1] = (byte)(v >> 8);
    }
}
