using DnsServerCore.ApplicationCommon;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RouterLiveDns
{
    /// <summary>
    /// Live, self-contained multicast DNS resolver: joins 224.0.0.251:5353,
    /// sends a one-shot A query, waits briefly for a matching reply, and parses
    /// it. Deliberately hand-rolls the wire format (RFC 1035 message framing,
    /// which RFC 6762 mDNS reuses) rather than depending on Avahi's D-Bus API,
    /// so no extra sandboxing/D-Bus policy grant is needed for this app.
    /// Not cached: mDNS responders come and go far more transiently than the
    /// ARP table NeighborCache tracks, so every query gets a fresh probe.
    /// </summary>
    sealed class MdnsResolver : IDisposable
    {
        static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
        const int MdnsPort = 5353;
        const int SOL_SOCKET = 1;
        const int SO_REUSEPORT = 15; // Linux sockopt, no SocketOptionName equivalent in the BCL

        readonly IDnsServer _dnsServer;
        readonly string _interfaceName;
        readonly int _timeoutMs;

        public MdnsResolver(IDnsServer dnsServer, string interfaceName, int timeoutMs)
        {
            _dnsServer = dnsServer;
            _interfaceName = interfaceName;
            _timeoutMs = timeoutMs;
        }

        public void Dispose()
        {
            //sockets are opened and closed per-query; nothing persistent to release
        }

        public async Task<IPAddress?> ResolveAsync(string name)
        {
            try
            {
                return await ResolveInternalAsync(name);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
                return null;
            }
        }

        async Task<IPAddress?> ResolveInternalAsync(string name)
        {
            byte[] query = BuildQuery(name);

            using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            try
            {
                //so this coexists with avahi-daemon's own listener on the same group/port
                socket.SetRawSocketOption(SOL_SOCKET, SO_REUSEPORT, BitConverter.GetBytes(1));
            }
            catch
            {
                //best effort; ReuseAddress above is the fallback if unsupported
            }

            socket.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));

            //resolved lazily per-query (not cached at construction) since br-lan may
            //not exist yet when the app initializes - matches the race class already
            //called out for the DNS listener itself in modules/dns-technitium.nix
            IPAddress? localAddress = GetInterfaceAddress(_interfaceName);

            if (localAddress is not null)
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localAddress.GetAddressBytes());

            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastGroup, localAddress ?? IPAddress.Any));

            await socket.SendToAsync(new ArraySegment<byte>(query), SocketFlags.None, new IPEndPoint(MulticastGroup, MdnsPort));

            byte[] buffer = new byte[4096];
            using CancellationTokenSource cts = new CancellationTokenSource(_timeoutMs);

            try
            {
                while (true)
                {
                    SocketReceiveFromResult result = await socket.ReceiveFromAsync(
                        new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);

                    IPAddress? answer = TryParseAnswer(buffer, result.ReceivedBytes, name);
                    if (answer is not null)
                        return answer;
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        }

        static IPAddress? GetInterfaceAddress(string interfaceName)
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!nic.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (UnicastIPAddressInformation addr in nic.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        return addr.Address;
                }
            }

            return null;
        }

        static byte[] BuildQuery(string name)
        {
            using System.IO.MemoryStream stream = new System.IO.MemoryStream();

            WriteUInt16(stream, 0); //ID
            WriteUInt16(stream, 0); //flags: standard query
            WriteUInt16(stream, 1); //QDCOUNT
            WriteUInt16(stream, 0); //ANCOUNT
            WriteUInt16(stream, 0); //NSCOUNT
            WriteUInt16(stream, 0); //ARCOUNT

            WriteName(stream, name);
            WriteUInt16(stream, 1); //QTYPE A
            WriteUInt16(stream, 1); //QCLASS IN

            return stream.ToArray();
        }

        static void WriteUInt16(System.IO.Stream stream, ushort value)
        {
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        static void WriteName(System.IO.Stream stream, string name)
        {
            foreach (string label in name.Split('.'))
            {
                if (label.Length == 0)
                    continue;

                byte[] bytes = Encoding.ASCII.GetBytes(label);
                stream.WriteByte((byte)bytes.Length);
                stream.Write(bytes, 0, bytes.Length);
            }

            stream.WriteByte(0);
        }

        static IPAddress? TryParseAnswer(byte[] buffer, int length, string expectedName)
        {
            try
            {
                if (length < 12)
                    return null;

                int qdcount = (buffer[4] << 8) | buffer[5];
                int ancount = (buffer[6] << 8) | buffer[7];
                if (ancount == 0)
                    return null;

                int offset = 12;

                for (int i = 0; i < qdcount; i++)
                {
                    ReadName(buffer, ref offset);
                    offset += 4; //QTYPE + QCLASS
                }

                for (int i = 0; i < ancount; i++)
                {
                    string name = ReadName(buffer, ref offset);

                    int type = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2; //TYPE
                    offset += 2; //CLASS (top bit may be the mDNS cache-flush bit; ignored)
                    offset += 4; //TTL
                    int rdlength = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;

                    if ((type == 1) && (rdlength == 4) && name.Equals(expectedName, StringComparison.OrdinalIgnoreCase))
                        return new IPAddress(new[] { buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3] });

                    offset += rdlength;
                }
            }
            catch
            {
                //malformed/unexpected packet on a shared multicast group; ignore and keep waiting
            }

            return null;
        }

        static string ReadName(byte[] buffer, ref int offset)
        {
            StringBuilder sb = new StringBuilder();
            int jumped = -1;
            int guard = 0;

            while (true)
            {
                if (++guard > 128)
                    break; //compression loop guard

                byte len = buffer[offset];

                if (len == 0)
                {
                    offset++;
                    break;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    int pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
                    if (jumped < 0)
                        jumped = offset + 2;

                    offset = pointer;
                    continue;
                }

                offset++;

                if (sb.Length > 0)
                    sb.Append('.');

                sb.Append(Encoding.ASCII.GetString(buffer, offset, len));
                offset += len;
            }

            if (jumped >= 0)
                offset = jumped;

            return sb.ToString();
        }
    }
}
