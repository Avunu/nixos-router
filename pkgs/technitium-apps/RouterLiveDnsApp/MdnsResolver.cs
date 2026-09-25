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
    ///
    /// Answers are trusted only as far as the LAN they came from (RFC 6762 §11):
    /// a reply counts only if it is a response, was sent from an address on the
    /// resolver interface's own subnet, and names an address on that subnet.
    /// The socket is bound to 0.0.0.0:5353, so without the source check any host
    /// able to reach the port could race in a forged answer; without the answer
    /// check a LAN device could point a name anywhere, loopback and public
    /// addresses included (DNS rebinding).
    /// </summary>
    sealed class MdnsResolver : IDisposable
    {
        static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
        const int MdnsPort = 5353;
        const int SOL_SOCKET = 1;
        const int SO_REUSEPORT = 15; // Linux sockopt, no SocketOptionName equivalent in the BCL

        //every *.local query from any client opens a socket and sends a
        //multicast probe; past this many in flight, further ones get no answer
        const int MaxConcurrentProbes = 8;

        readonly IDnsServer _dnsServer;
        readonly string _interfaceName;
        readonly int _timeoutMs;
        readonly SemaphoreSlim _probes = new SemaphoreSlim(MaxConcurrentProbes, MaxConcurrentProbes);

        public MdnsResolver(IDnsServer dnsServer, string interfaceName, int timeoutMs)
        {
            _dnsServer = dnsServer;
            _interfaceName = interfaceName;
            _timeoutMs = timeoutMs;
        }

        public void Dispose()
        {
            //sockets are opened and closed per-query; nothing persistent to release.
            //_probes is deliberately not disposed: a reconfigure disposes this
            //resolver while queries may still be in flight, and their Release()
            //must not throw (a SemaphoreSlim holds no handle until one is asked for)
        }

        public async Task<IPAddress?> ResolveAsync(string name)
        {
            if (!_probes.Wait(0))
                return null; //saturated: an unanswered name, not a queue

            try
            {
                return await ResolveInternalAsync(name);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
                return null;
            }
            finally
            {
                _probes.Release();
            }
        }

        async Task<IPAddress?> ResolveInternalAsync(string name)
        {
            //resolved lazily per-query (not cached at construction) since br-lan may
            //not exist yet when the app initializes - matches the race class already
            //called out for the DNS listener itself in modules/dns-technitium.nix.
            //Without the interface's subnet there is nothing to validate answers
            //against, so there is no answer.
            UnicastIPAddressInformation? local = GetInterfaceAddress(_interfaceName);
            if (local is null)
                return null;

            IPAddress localAddress = local.Address;
            int prefixLength = local.PrefixLength;

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

            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localAddress.GetAddressBytes());
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastGroup, localAddress));

            await socket.SendToAsync(new ArraySegment<byte>(query), SocketFlags.None, new IPEndPoint(MulticastGroup, MdnsPort));

            byte[] buffer = new byte[4096];
            using CancellationTokenSource cts = new CancellationTokenSource(_timeoutMs);

            try
            {
                while (true)
                {
                    SocketReceiveFromResult result = await socket.ReceiveFromAsync(
                        new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);

                    if ((result.RemoteEndPoint is not IPEndPoint remote) || !InSubnet(remote.Address, localAddress, prefixLength))
                        continue; //not from the LAN this resolver serves

                    IPAddress? answer = TryParseAnswer(buffer, result.ReceivedBytes, name);
                    if ((answer is not null) && InSubnet(answer, localAddress, prefixLength))
                        return answer;
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        }

        static UnicastIPAddressInformation? GetInterfaceAddress(string interfaceName)
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!nic.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (UnicastIPAddressInformation addr in nic.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        return addr;
                }
            }

            return null;
        }

        static bool InSubnet(IPAddress address, IPAddress network, int prefixLength)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if ((address.AddressFamily != AddressFamily.InterNetwork) || (prefixLength < 0) || (prefixLength > 32))
                return false;

            uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
            return (ToUInt32(address) & mask) == (ToUInt32(network) & mask);
        }

        static uint ToUInt32(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
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

                if ((buffer[2] & 0x80) == 0)
                    return null; //QR clear: another host's query, not an answer

                int qdcount = (buffer[4] << 8) | buffer[5];
                int ancount = (buffer[6] << 8) | buffer[7];
                if (ancount == 0)
                    return null;

                int offset = 12;

                for (int i = 0; i < qdcount; i++)
                {
                    ReadName(buffer, length, ref offset);
                    offset += 4; //QTYPE + QCLASS
                }

                for (int i = 0; i < ancount; i++)
                {
                    string name = ReadName(buffer, length, ref offset);

                    if (offset + 10 > length)
                        return null;

                    int type = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2; //TYPE
                    offset += 2; //CLASS (top bit may be the mDNS cache-flush bit; ignored)
                    offset += 4; //TTL
                    int rdlength = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;

                    if (offset + rdlength > length)
                        return null;

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

        //bounded by the bytes actually received, not the buffer: the rest of the
        //buffer is whatever an earlier datagram left there
        static string ReadName(byte[] buffer, int length, ref int offset)
        {
            StringBuilder sb = new StringBuilder();
            int jumped = -1;
            int guard = 0;

            while (true)
            {
                if (++guard > 128)
                    break; //compression loop guard

                if (offset >= length)
                    throw new IndexOutOfRangeException("name runs past the datagram");

                byte len = buffer[offset];

                if (len == 0)
                {
                    offset++;
                    break;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    if (offset + 1 >= length)
                        throw new IndexOutOfRangeException("pointer runs past the datagram");

                    int pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
                    if (jumped < 0)
                        jumped = offset + 2;

                    offset = pointer;
                    continue;
                }

                offset++;

                if (offset + len > length)
                    throw new IndexOutOfRangeException("label runs past the datagram");

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
