---
title: Tune the rules
description: Triage Suricata events, then disable, suppress or drop signatures, set actions per rule category, and add your own local rules.
code:
  - modules/threat-protection.nix
  - pkgs/cockpit-router/src/suricata.tsx
  - pkgs/cockpit-router/src/suricata-events.ts
  - pkgs/cockpit-router/src/suricata-categories.json
  - pkgs/cockpit-router/src/suricata-rules.ts
  - pkgs/cockpit-router/src/ip-math.ts
  - modules/lib/net.nix
---

# Tune the rules

The downloaded rule sets are written for every network, so some rules will fire on traffic that's normal on yours. Tuning means working through the events Suricata reports in IDS mode, silencing the false positives, and choosing what to drop before you [switch to IPS mode](/docs/threat-protection/setup/#switch-to-ips-mode). Most of the work starts from a single event.

## The triage workflow

1. Open **Threat Protection → Statistics** and look at **Top signatures** to see which signatures fire most.
2. Open **Threat Protection → Events** and filter to one of those signatures.
3. Click an event to open its details, and decide whether the traffic is legitimate.
4. Under **Add self-defined policy**, pick an action and click **Save policy**.
5. Review the result on the **Policies** tab, then apply it.

Repeat until the remaining events are ones you want to see.

## Find events

The **Events** tab loads up to 500 of the most recent alerts and drops, then adds new ones as they arrive. It keeps up to 2,000 rows. The toolbar has three filters:

- The search box, **Filter by IP, signature, category, SID**, matches text in the source or destination IP, protocol, event type, signature name, category or SID. It ignores case.
- The severity list: **All severities**, **High**, **Medium** or **Low**. Suricata's priority 1 is High, 2 is Medium, and 3 or higher is Low.
- The action list: **All actions**, **Blocked** or **Alerted**.

Click a row to open the event. The details show **Time**, **Signature** with its SID, **Category**, **Severity / action**, and **Source → Destination** with ports and protocol.

## Add a self-defined policy

Below the details, **Add self-defined policy** turns the event into a rule change. Choose an **Action**:

| Action | What it does | Use it when |
| --- | --- | --- |
| **Disable signature** (preselected) | Removes the rule from the rule set. | The signature fires on legitimate traffic from many hosts: a false positive everywhere. |
| **Suppress for a host** | Keeps the rule, but records no events for one host or subnet. | The traffic is legitimate for one host, such as a vulnerability scanner you run, but the signature is useful for everyone else. |
| **Drop (IPS mode)** | Rewrites the rule to drop matching packets. It takes effect only in IPS mode. | You've confirmed the traffic is malicious. |
| **Alert (default)** | Changes nothing; it records that you reviewed the signature. | You want to keep watching it, with a comment saying why. |

For **Suppress for a host**, two more fields appear:

- **Host IP / subnet**: filled in with the event's source address. Change it to the host or subnet to exempt, for example `192.168.1.5` or `192.168.1.0/24`. It must be one IPv4 or IPv6 address or prefix; until it is, the field is marked and **Save policy** stays unavailable.
- **Track by**: which side of the connection that address must be on. **Source** if the host started the flagged traffic, **Destination** if it received it, **Either** for both.

Add a **Comment** so you remember why, then click **Save policy**. The message "Added. Review under Policies, then apply from the changes tray." confirms it's in the settings file. It isn't active until you apply: click **Apply** in the **Unapplied changes** bar, or **Save & apply** on the **Policies** tab.

Each save adds a new entry, even when the SID already has one. Check the **Policies** tab for duplicates.

If the event has no signature ID, the form is replaced by "This event has no signature ID, so no policy can be derived from it."

## The Policies tab

**Threat Protection → Policies** has three sections. Changes there take effect when you click **Save & apply** (or **Save**, then **Apply**).

### Rule categories

Each ET Open rule file appears as a card with a short description and a list: **Default**, **Disable** or **Drop**. In IDS mode, **Drop** reads **Drop (needs IPS)**; you can set it, but it has no effect until IPS mode is on. **Default** leaves the rules as the source ships them.

| Card | Rule file |
| --- | --- |
| Attack responses | `emerging-attack_response.rules` |
| Malware | `emerging-malware.rules` |
| Trojans | `emerging-trojan.rules` |
| Mobile malware | `emerging-mobile_malware.rules` |
| Exploits | `emerging-exploit.rules` |
| Exploit kits | `emerging-exploit_kit.rules` |
| Phishing | `emerging-phishing.rules` |
| Coin miners | `emerging-coinminer.rules` |
| Worms | `emerging-worm.rules` |
| Current events | `emerging-current_events.rules` |
| Web client | `emerging-web_client.rules` |
| Web server | `emerging-web_server.rules` |
| Web apps | `emerging-web_specific_apps.rules` |
| SQL | `emerging-sql.rules` |
| Shellcode | `emerging-shellcode.rules` |
| Scans | `emerging-scan.rules` |
| Denial of service | `emerging-dos.rules` |
| DNS | `emerging-dns.rules` |
| Tor | `emerging-tor.rules` |
| User agents | `emerging-user_agents.rules` |
| Policy | `emerging-policy.rules` |
| Informational | `emerging-info.rules` |
| SCADA / ICS | `emerging-scada.rules` |
| Peer-to-peer | `emerging-p2p.rules` |
| Chat | `emerging-chat.rules` |
| Games | `emerging-games.rules` |

A category action covers every rule in that file, including rules added by future updates. Prefer signature policies when only a few rules in a category bother you.

### Signature policies

A table of per-signature overrides, with **SID**, **Action** (**Alert**, **Drop** or **Disable**) and **Comment** columns, and **Remove** on each row. Entries usually come from the Events tab. To add one by hand, type the number in **Signature ID** and click **Add signature**; it's added with the action **Disable**.

### Suppressions

A table of per-host exemptions, with **SID**, **Host**, **Track** (**Source**, **Destination** or **Either**) and **Comment** columns. To add one by hand, fill in **Signature ID** and **Host IP / subnet** and click **Add suppression**; it tracks **Source** until you change it.

The host must be one IPv4 or IPv6 address or prefix, such as `192.168.1.5`, `192.168.1.0/24` or `2001:db8::/48`; **Add suppression** stays unavailable until it is. An IPv6 prefix length must be 1 to 128, so `::/0` isn't accepted. An entry that isn't, for example from an edited settings file, is marked in the table, and the build refuses it with `router.suricata.suppressions: SID 2100498 has an invalid host 'nas' — use an IPv4 or IPv6 address or CIDR prefix`. Remove it and add it again.

### What policies can't change

Category and signature policies are applied by `suricata-update` to the downloaded rules. Local rules, both the built-in ones below and your extra rules, are loaded directly, so a **Disable** or **Drop** policy on their SIDs has no effect. Suppressions work for every rule, local ones included.

## Extra local rules

To add your own Suricata rules:

1. Open **Threat Protection → Settings**.
2. Type or paste the rules into **Extra local rules**, one per line.
3. Click **Save & apply**.

For example, this rule alerts when a device on your network opens a Remote Desktop connection to a host on the internet:

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:"LOCAL outbound RDP connection attempt"; flow:to_server; flags:S; sid:1000100; rev:1;)
```

`flags:S` matches the connection's opening SYN packet, so it alerts once per attempt rather than on every packet. To block the connection instead, write `drop` in place of `alert`. A `drop` rule you write yourself drops in IDS mode too; the mode switch only controls the drop actions on the **Policies** tab.

Keep these rules in mind:

- **Pick unused SIDs.** SIDs 1000000 to 1999999 are the conventional range for local rules. The built-in rules use 1000001 to 1000011, so start yours at 1000100 or above.
- **Start each rule at the beginning of its line.** Suricata skips a line that starts with a space or tab, as it does a `#` comment. To split a long rule, end the line with `\` and carry on below.
- **A broken rule fails the apply.** As you type, the box flags common mistakes: lines that aren't rules, rules without a SID, SIDs used twice and the built-in SIDs. When you apply, Suricata tests the local rules before anything changes. A rule that doesn't parse, or a SID that's already loaded, ends the apply with `router.suricata: Suricata rejected the configuration.`; the lines above it in the log name the rule. Suricata keeps running on the rules it had until you fix it. The test doesn't load the downloaded rules, so a clash with one of their SIDs still shows up only when Suricata starts; see [Events and logs](/docs/threat-protection/monitoring/#suricata-wont-start-or-is-slow-to-start).
- **A rule that reads a file needs that test turned off.** The test loads the local rules from the Nix store, not from `/etc/suricata/rules`, and it can't see `/var/lib`. So a rule that loads its own list, such as a `filemd5` or `filesha256` file or a `dataset` with `load`, fails it even when the file is on the router: the log shows `opening hash file` or `failed to set up dataset`. The web UI has no switch for this. Set `router.suricata.checkRulesAtBuild = false;` in Nix, where you ship the file too, for example with `environment.etc."suricata/rules/md5-blocklist.txt"`; see [Nix overrides the file](/docs/start/settings-file/#nix-overrides-the-file). With the test off, a broken rule no longer fails the apply. Suricata keeps running when it reloads the rules, but the broken rule stops it the next time it starts, such as after a reboot or a system update; the **Extra local rules** help text says so. Suppression hosts are still checked.
- **`$HOME_NET` holds no IPv6 LAN or guest prefix.** A rule keyed on it won't match your hosts' IPv6 traffic; see [What counts as your network](/docs/threat-protection/#what-counts-as-your-network).
- **`$HTTP_PORTS` is port 80 only.**

The router writes the built-in rules, then yours, to `/etc/suricata/rules/local.rules`.

### Built-in local rules

These rules support the router's DNS and SafeSearch enforcement. They all alert only.

| SID | Message starts with | Alerts on |
| --- | --- | --- |
| 1000001 | `POLICY DoT bypass attempt` | TLS from `$HOME_NET` to port 853 (DNS over TLS) |
| 1000002 to 1000007 | `POLICY DoH bypass` | TLS to port 443 whose server name contains `cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, `dns.nextdns.io`, `doh.mullvad.net` or `dns.adguard.com` |
| 1000010 and 1000011 | `POLICY SafeSearch bypass` | HTTP requests on port 80 whose URI contains `safe=off` or `safeSearch=off` |

What to expect from them:

- The firewall drops port 853 from the LAN and guest networks before Suricata sees it, so 1000001 fires only for WireGuard clients.
- The SafeSearch rules see plain HTTP only. Searches over HTTPS are encrypted, so these rarely fire.
- Blocking DoH providers is done in DNS; see [DNS enforcement](/docs/access-policies/dns-enforcement/). These rules only report attempts.
- Policies can't disable them. If one is noisy, suppress it for the host or subnet.

## In the settings file

The Policies and Settings tabs edit these keys. The SIDs below are examples.

```json
{
  "suricata": {
    "enable": true,
    "mode": "ips",
    "categories": {
      "emerging-malware.rules": "drop",
      "emerging-games.rules": "disabled"
    },
    "policies": [
      { "sid": 2013028, "action": "drop", "comment": "confirmed on 192.168.1.40" },
      { "sid": 2019401, "action": "disable", "comment": "false positive on every host" }
    ],
    "suppressions": [
      { "sid": 2100498, "ip": "192.168.1.5", "track": "by_src", "comment": "internal scanner" }
    ],
    "extraRules": "alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:\"LOCAL outbound RDP connection attempt\"; flow:to_server; flags:S; sid:1000100; rev:1;)\n"
  }
}
```

- `categories` maps a rule file name to `enabled`, `disabled` or `drop`. `enabled` is the same as leaving the file out; the UI removes the key when you choose **Default**. You can use any rule file name here, not only the 26 the UI shows.
- `policies` entries take `sid`, `action` (`alert`, `drop` or `disable`; default `alert`) and an optional `comment`.
- `suppressions` entries take `sid`, `ip`, `track` (`by_src`, `by_dst` or `by_either`; default `by_src`) and an optional `comment`.
- `extraRules` is one string, with a newline between rules.

## How settings become rule files

On each rebuild, the router renders your settings into three files:

- **disable.conf**, passed to `suricata-update`. It lists the NixOS module's default disabled rules (the DNP3 event rules), a `group:` line for each category set to `disabled`, and each SID with the action `disable`. Those rules are left out of the rule set.
- **drop.conf**, passed to `suricata-update`. In IPS mode it lists a `group:` line for each category set to `drop`, and each SID with the action `drop`; those rules are rewritten to drop. In IDS mode the file is empty.
- **threshold.config**, read by Suricata itself. It has one `suppress` line per suppression.

For the example above, the router-generated lines are:

```text
# disable.conf
group:emerging-games.rules
2019401

# drop.conf (empty in IDS mode)
group:emerging-malware.rules
2013028

# threshold.config
suppress gen_id 1, sig_id 2100498, track by_src, ip 192.168.1.5
```

Signatures with the action `alert` appear in none of them. `suricata-update` applies the disable and drop lists when it builds `/var/lib/suricata/rules/suricata.rules`. It runs on every apply and daily; see [Rule updates](/docs/threat-protection/setup/#rule-updates).
