using DnsServerCore.ApplicationCommon;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RouterLiveDns
{
    /// <summary>
    /// Attached as an apex APP record to two zones (see modules/dns-technitium.nix):
    ///  - hostZone (router.lan.domain), always: resolves router.hosts entries that
    ///    have no static IP to their current live LAN address (NeighborCache).
    ///  - "local", only when router.dns.technitium.resolveMdns is enabled: resolves
    ///    arbitrary *.local names via a live mDNS probe (MdnsResolver).
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
            _neighborCache = new NeighborCache(dnsServer, newConfig.IpTool, newConfig.NeighborRefreshIntervalSeconds, newConfig.SlugToMac);

            _mdnsResolver?.Dispose();
            _mdnsResolver = new MdnsResolver(dnsServer, newConfig.MdnsInterface, newConfig.MdnsQueryTimeoutMs);

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
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
            else
            {
                address = await _mdnsResolver.ResolveAsync(question.Name);
            }

            if (address is null)
                return null;

            DnsResourceRecord[] answer = { new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)) };

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answer);
        }

        public string Description => "Resolves adopted router.hosts entries without a static IP to their current live LAN address, and (in the \"local\" zone) live mDNS *.local names.";

        public string? ApplicationRecordDataTemplate => null;
    }
}
