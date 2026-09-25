using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;

namespace RouterLiveDns
{
    /// <summary>
    /// Keeps a live MAC -&gt; IPv4 map, refreshed on a background timer from the
    /// kernel's ARP/NDP neighbor table (via `ip -j neigh`, the same mechanism
    /// pkgs/cockpit-router/src/hosts-live.ts already uses for display). Query
    /// handling only ever reads the in-memory snapshot, never blocks on a refresh.
    ///
    /// Entries are keyed by (device, MAC), and a host resolves only through its
    /// own network's bridge. A MAC is just a claim: without the device, a guest
    /// client cloning a LAN host's MAC would take over that host's name, and LAN
    /// clients would follow it onto the guest network.
    /// </summary>
    sealed class NeighborCache : IDisposable
    {
        readonly IDnsServer _dnsServer;
        readonly string _ipTool;
        readonly IReadOnlyDictionary<string, DynamicHost> _hosts;
        readonly Timer _timer;

        //"<dev> <mac>" -> address, plus "* <mac>" for hosts whose config names no device
        volatile Dictionary<string, IPAddress> _macToIp = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);

        public NeighborCache(IDnsServer dnsServer, string ipTool, int refreshIntervalSeconds, IReadOnlyDictionary<string, DynamicHost> hosts)
        {
            _dnsServer = dnsServer;
            _ipTool = ipTool;
            _hosts = hosts;

            int intervalMs = Math.Max(5, refreshIntervalSeconds) * 1000;
            _timer = new Timer(RefreshCallback, null, 0, intervalMs);
        }

        public void Dispose()
        {
            _timer.Dispose();
        }

        public IPAddress? ResolveBySlug(string slug)
        {
            if (!_hosts.TryGetValue(slug, out DynamicHost? host))
                return null;

            //volatile read: a snapshot, never mutated in place, so no locking needed
            Dictionary<string, IPAddress> snapshot = _macToIp;

            return snapshot.TryGetValue(Key(host.Interface, host.Mac), out IPAddress? address) ? address : null;
        }

        static string Key(string device, string mac)
        {
            return (string.IsNullOrEmpty(device) ? "*" : device) + " " + mac;
        }

        void RefreshCallback(object? state)
        {
            try
            {
                Refresh();
            }
            catch (Exception ex)
            {
                //keep the previous (possibly stale) cache rather than blanking it out
                _dnsServer.WriteLog(ex);
            }
        }

        void Refresh()
        {
            using Process process = new Process();
            process.StartInfo.FileName = _ipTool;
            process.StartInfo.ArgumentList.Add("-j");
            process.StartInfo.ArgumentList.Add("neigh");
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;

            process.Start();

            //read both pipes concurrently and bound the wait: a synchronous
            //ReadToEnd would block until `ip` exits, so the timeout never fired
            System.Threading.Tasks.Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            System.Threading.Tasks.Task<string> stderr = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(5000))
            {
                try
                {
                    process.Kill(true);
                }
                catch (InvalidOperationException)
                {
                    //exited between the timeout and the kill
                }

                return;
            }

            string output = stdout.GetAwaiter().GetResult();
            stderr.GetAwaiter().GetResult();

            if (process.ExitCode != 0)
                return;

            Dictionary<string, IPAddress> freshMap = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);

            using JsonDocument doc = JsonDocument.Parse(output);

            foreach (JsonElement entry in doc.RootElement.EnumerateArray())
            {
                if (!entry.TryGetProperty("dst", out JsonElement dstEl))
                    continue;

                string? dst = dstEl.GetString();
                if (string.IsNullOrEmpty(dst) || !IPAddress.TryParse(dst, out IPAddress? address))
                    continue;

                if (address.AddressFamily != AddressFamily.InterNetwork)
                    continue; //v1: IPv4 only, see plan's explicit non-goals

                if (!entry.TryGetProperty("lladdr", out JsonElement llEl))
                    continue;

                string? mac = llEl.GetString();
                if (string.IsNullOrEmpty(mac))
                    continue;

                if (IsFailed(entry))
                    continue;

                string? dev = entry.TryGetProperty("dev", out JsonElement devEl) ? devEl.GetString() : null;
                if (string.IsNullOrEmpty(dev))
                    continue;

                //most recent entry wins if the table has more than one per device
                freshMap[Key(dev, mac)] = address;
                freshMap[Key(string.Empty, mac)] = address;
            }

            _macToIp = freshMap;
        }

        static bool IsFailed(JsonElement entry)
        {
            if (!entry.TryGetProperty("state", out JsonElement stateEl))
                return false;

            if (stateEl.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement s in stateEl.EnumerateArray())
                {
                    if (string.Equals(s.GetString(), "FAILED", StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                return false;
            }

            if (stateEl.ValueKind == JsonValueKind.String)
                return string.Equals(stateEl.GetString(), "FAILED", StringComparison.OrdinalIgnoreCase);

            return false;
        }
    }
}
