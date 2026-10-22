using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RouterLiveDns
{
    /// <summary>
    /// Attached as an apex APP record to up to three zones (see modules/dns-technitium.nix):
    ///  - hostZone (router.lan.domain), always: resolves router.hosts entries that
    ///    have no static IP to their current live LAN address (NeighborCache).
    ///  - "local", only when router.dns.technitium.resolveMdns is enabled: resolves
    ///    arbitrary *.local names via a live mDNS probe (MdnsResolver).
    ///  - the block-check zone, only while the router's HTTPS portal is on: the
    ///    oracle router-logd asks whether a name is blocked for a given client
    ///    (ProcessBlockCheckAsync).
    ///
    /// Returning null here is "I don't know this name" - Technitium's own
    /// ProcessAPPAsync then falls through to the owning zone's FWD record
    /// (hostZone, a Forwarder zone) or synthesizes NODATA/NXDOMAIN (the "local"
    /// Primary zone), so no fallback logic needs to be duplicated here.
    /// </summary>
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        static readonly JsonDocumentOptions JsonParseOptions = new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip };

        IDnsServer? _dnsServer;
        Config _config = new Config();
        NeighborCache? _neighborCache;
        MdnsResolver? _mdnsResolver;

        public void Dispose()
        {
            _neighborCache?.Dispose();
            _mdnsResolver?.Dispose();
        }

        public Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            _dnsServer = dnsServer;

            Config newConfig;
            using (JsonDocument jsonDocument = JsonDocument.Parse(string.IsNullOrEmpty(config) ? "{}" : config, JsonParseOptions))
            {
                newConfig = Config.Parse(jsonDocument.RootElement);
            }

            _config = newConfig;

            //InitializeAsync is called again on every config push (adoption -> rebuild
            //-> reconcile), so the previous refresh timer must be torn down first or
            //repeated reconciles leak concurrent refresh loops
            _neighborCache?.Dispose();
            _neighborCache = new NeighborCache(dnsServer, newConfig.IpTool, newConfig.NeighborRefreshIntervalSeconds, newConfig.DynamicHosts);

            _mdnsResolver?.Dispose();
            _mdnsResolver = new MdnsResolver(dnsServer, newConfig.MdnsInterface, newConfig.MdnsQueryTimeoutMs);

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            //before the A/ANY filter below: the oracle answers TXT
            if ((_config.BlockCheckZone.Length > 0) && zoneName.Equals(_config.BlockCheckZone, StringComparison.OrdinalIgnoreCase))
                return await ProcessBlockCheckAsync(request, remoteEP, isRecursionAllowed, appRecordName);

            if ((_neighborCache is null) || (_mdnsResolver is null))
                return null; //not yet initialized

            DnsQuestionRecord question = request.Question[0];

            if ((question.Type != DnsResourceRecordType.A) && (question.Type != DnsResourceRecordType.ANY))
                return null;

            //a query for the zone apex itself never resolves to a device address
            if (question.Name.Length == appRecordName.Length)
                return null;

            IPAddress? address;

            if (zoneName.Equals(_config.HostZone, StringComparison.OrdinalIgnoreCase))
            {
                //only direct <slug>.<hostZone> names are handled here, not deeper subdomains
                string label = question.Name.Substring(0, question.Name.Length - appRecordName.Length - 1);
                if (label.Contains('.'))
                    return null;

                address = _neighborCache.ResolveBySlug(label);
            }
            else if (zoneName.Equals("local", StringComparison.OrdinalIgnoreCase))
            {
                address = await _mdnsResolver.ResolveAsync(question.Name);
            }
            else
            {
                //a zone this app does not (yet) know: the APP record can exist
                //before the config naming its zone has been pushed
                return null;
            }

            if (address is null)
                return null;

            DnsResourceRecord[] answer = { new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)) };

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answer);
        }

        /// <summary>
        /// The block-check oracle behind router-logd's HTTPS portal. Advanced
        /// Blocking picks a policy from the address that sent the query only, and
        /// router-logd's own queries come from loopback (the bypass group), so the
        /// question "is this name blocked for that device?" can only be asked from
        /// in here, where DirectQueryAsync can present the device's address to the
        /// query pipeline. The Block Page app does the same for {BLOCKING-INFO}.
        ///
        /// Question: TXT &lt;host&gt;.&lt;client-ip-label&gt;.&lt;zone&gt;, where the label is the
        /// address with its separators written as '-' (10-48-4-50, fd00--1).
        /// Answer: one TXT string "rcode=&lt;probe rcode&gt;; &lt;Advanced Blocking report&gt;"
        /// when the host is blocked for that client, an empty NOERROR when it is
        /// not. The report is the app's own EDE text
        /// ("source=advanced-blocking-app; group=...; ..."), which it attaches
        /// because compile_policies.py sets allowTxtBlockingReport.
        /// </summary>
        async Task<DnsDatagram?> ProcessBlockCheckAsync(DnsDatagram request, IPEndPoint remoteEP, bool isRecursionAllowed, string appRecordName)
        {
            IDnsServer? dnsServer = _dnsServer;
            if (dnsServer is null)
                return null;

            //the zone's own query access (Deny) already refuses everyone but the
            //router itself; this is the second lock on the same door
            IPAddress requester = remoteEP.Address;
            if (requester.IsIPv4MappedToIPv6)
                requester = requester.MapToIPv4();

            if (!IPAddress.IsLoopback(requester))
                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question);

            DnsQuestionRecord question = request.Question[0];
            if (question.Type != DnsResourceRecordType.TXT)
                return null;

            string suffix = "." + appRecordName;
            string name = question.Name.ToLowerInvariant();
            if (!name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return null;

            string prefix = name.Substring(0, name.Length - suffix.Length);
            int split = prefix.LastIndexOf('.');
            if (split <= 0)
                return null;

            string host = prefix.Substring(0, split);
            IPAddress? client = ParseClientLabel(prefix.Substring(split + 1));

            //a host under the oracle's own zone would come straight back here
            //(DirectQueryAsync still processes APP records), and the router's own
            //addresses are the bypass group, never a device's policy
            if ((client is null) || IPAddress.IsLoopback(client) || client.Equals(IPAddress.Any) || client.Equals(IPAddress.IPv6Any))
                return null;

            if (host.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) || host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return null;

            DnsDatagram probe;
            try
            {
                //A with EDNS, as the Block Page app asks: Advanced Blocking attaches
                //its report only to requests that carry EDNS, and an A answer is
                //usually cached already, since the browser has just resolved it
                probe = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN)], udpPayloadSize: DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE);
            }
            catch (Exception)
            {
                return null; //not a domain name
            }

            DnsDatagram response;
            try
            {
                response = await dnsServer.DirectQueryAsync(probe, new IPEndPoint(client, 0), _config.BlockCheckTimeoutMs);
            }
            catch (TimeoutException)
            {
                //Advanced Blocking answers a blocked name at once, before any
                //recursion, so a probe that ran out of time was not blocked
                return EmptyAnswer(request, isRecursionAllowed);
            }
            catch (Exception ex)
            {
                dnsServer.WriteLog(ex);
                return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question);
            }

            string? report = FindBlockingReport(response);
            if (report is null)
                return EmptyAnswer(request, isRecursionAllowed);

            //the rcode tells router-logd the policy's response type: NxDomain
            //policies are for devices that should fail fast, and get no page
            string text = "rcode=" + response.RCODE.ToString() + "; " + report;
            DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 0, new DnsTXTRecordData(text))];

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answer);
        }

        static DnsDatagram EmptyAnswer(DnsDatagram request, bool isRecursionAllowed)
        {
            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question);
        }

        static string? FindBlockingReport(DnsDatagram response)
        {
            List<EDnsExtendedDnsErrorOptionData> errors = new List<EDnsExtendedDnsErrorOptionData>();

            if (response.EDNS is not null)
            {
                foreach (EDnsOption option in response.EDNS.Options)
                {
                    if ((option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR) && (option.Data is EDnsExtendedDnsErrorOptionData ede))
                        errors.Add(ede);
                }
            }

            errors.AddRange(response.DnsClientExtendedErrors);

            foreach (EDnsExtendedDnsErrorOptionData ede in errors)
            {
                if ((ede.InfoCode == EDnsExtendedDnsErrorCode.Blocked) && (ede.ExtraText is not null) && ede.ExtraText.StartsWith("source=advanced-blocking-app", StringComparison.Ordinal))
                    return ede.ExtraText;
            }

            return null;
        }

        /// <summary>
        /// 10-48-4-50 is IPv4 10.48.4.50; anything else of hex digits and dashes is
        /// IPv6 with ':' written as '-'. Strict about IPv4, since IPAddress.TryParse
        /// also takes shorthand such as "10.48".
        /// </summary>
        static IPAddress? ParseClientLabel(string label)
        {
            string[] parts = label.Split('-');

            if (parts.Length == 4)
            {
                byte[] octets = new byte[4];
                bool ok = true;

                for (int i = 0; i < 4; i++)
                {
                    if ((parts[i].Length == 0) || (parts[i].Length > 3) || !byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out octets[i]))
                    {
                        ok = false;
                        break;
                    }
                }

                if (ok)
                    return new IPAddress(octets);
            }

            foreach (char c in label)
            {
                if (!Uri.IsHexDigit(c) && (c != '-'))
                    return null;
            }

            if (IPAddress.TryParse(label.Replace('-', ':'), out IPAddress? v6) && (v6.AddressFamily == AddressFamily.InterNetworkV6))
                return v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;

            return null;
        }

        public string Description => "Resolves adopted router.hosts entries without a static IP to their current live LAN address, (in the \"local\" zone) live mDNS *.local names, and (in the block-check zone) whether a name is blocked for a given client.";

        public string? ApplicationRecordDataTemplate => null;
    }
}
