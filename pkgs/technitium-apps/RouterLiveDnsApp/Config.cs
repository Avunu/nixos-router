using System;
using System.Collections.Generic;
using System.Text.Json;

namespace RouterLiveDns
{
    /// <summary>
    /// Parsed form of the JSON pushed into this app's Technitium app-config slot
    /// (router.dns.technitium's "Router Live DNS" apps entry, see modules/dns-technitium.nix).
    /// </summary>
    /// <summary>
    /// A router.hosts entry without a static IP: its MAC, and the bridge of the
    /// network it belongs to, the only place its neighbor entry is believed.
    /// An empty Interface (a config written before the field existed) matches any.
    /// </summary>
    sealed record DynamicHost(string Mac, string Interface);

    sealed class Config
    {
        public string HostZone = string.Empty;
        public Dictionary<string, DynamicHost> DynamicHosts = new Dictionary<string, DynamicHost>(StringComparer.OrdinalIgnoreCase);
        public string IpTool = "ip";
        public int NeighborRefreshIntervalSeconds = 20;
        public string MdnsInterface = "br-lan";
        public int MdnsQueryTimeoutMs = 1200;

        public static Config Parse(JsonElement root)
        {
            Config config = new Config();

            if (root.TryGetProperty("hostZone", out JsonElement hz))
                config.HostZone = hz.GetString() ?? string.Empty;

            if (root.TryGetProperty("ipTool", out JsonElement ipTool))
                config.IpTool = ipTool.GetString() ?? "ip";

            if (root.TryGetProperty("neighborRefreshIntervalSeconds", out JsonElement interval) && (interval.ValueKind == JsonValueKind.Number))
                config.NeighborRefreshIntervalSeconds = interval.GetInt32();

            if (root.TryGetProperty("dynamicHosts", out JsonElement hosts) && (hosts.ValueKind == JsonValueKind.Array))
            {
                foreach (JsonElement host in hosts.EnumerateArray())
                {
                    string? slug = host.TryGetProperty("slug", out JsonElement s) ? s.GetString() : null;
                    string? mac = host.TryGetProperty("mac", out JsonElement m) ? m.GetString() : null;
                    string? iface = host.TryGetProperty("interface", out JsonElement i) ? i.GetString() : null;

                    if (!string.IsNullOrEmpty(slug) && !string.IsNullOrEmpty(mac))
                        config.DynamicHosts[slug] = new DynamicHost(mac, iface ?? string.Empty);
                }
            }

            if (root.TryGetProperty("mdns", out JsonElement mdns) && (mdns.ValueKind == JsonValueKind.Object))
            {
                if (mdns.TryGetProperty("interface", out JsonElement iface))
                    config.MdnsInterface = iface.GetString() ?? "br-lan";

                if (mdns.TryGetProperty("queryTimeoutMs", out JsonElement timeout) && (timeout.ValueKind == JsonValueKind.Number))
                    config.MdnsQueryTimeoutMs = timeout.GetInt32();
            }

            return config;
        }
    }
}
