---
title: Build a policy
description: Create an access policy in Cockpit, section by section, from categories and filter lists to allow rules and the blocked-query response.
code:
  - modules/access-policies.nix
  - modules/filter-catalog.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/cockpit-router/src/access-policies.tsx
  - pkgs/cockpit-router/src/policy-editors.tsx
  - pkgs/cockpit-router/src/ut-capitole.json
---

# Build a policy

A policy is a named set of DNS filters. This page walks through the policy editor on **Access Policies → Policies** in the order its sections appear, then shows a worked example for a school. To choose which clients a policy applies to, see [Assign policies](/docs/access-policies/assignments/).

## Before you start

- You need a Cockpit login with administrative access. See [The web UI](/docs/start/cockpit/).
- If a policy will target groups of devices, create those groups first on **Hosts → Groups**. See [Hosts and host groups](/docs/network/hosts/).
- The router downloads every list itself, so it needs internet access to the list hosts: `adguardteam.github.io`, `adaway.org` and `pgl.yoyo.org` for the standard filters, `raw.githubusercontent.com` for categories, and the host of any custom list you add.

## Create or edit a policy

1. Open **Access Policies → Policies**. The table lists your policies with the highest priority first. The **Filters** column counts each policy's categories, filters, lists and rules, and the **Assignments** column shows what it is assigned to.
2. Click **Add policy** to start an empty policy named "New policy", or click **Duplicate** on an existing one to copy it as "*name* copy". Click **Edit** to change a policy.
3. Work through the editor card, **Edit policy:** *name*. Its sections are described below.
4. Click **Save & apply**. The changes tray at the top of the page shows progress.

To remove a policy, click **Delete**. The default policy can't be deleted: make another policy the default first.

### Your first policy replaces Base

With no policies defined, the Policies tab says: "No policies defined — the backend synthesizes a "Base" policy until one is added." As soon as you add a policy, the router stops creating Base. The default policy is still named Base, though, so the next apply fails with:

```text
router.accessPolicies.defaultPolicy 'Base' is not a defined policy (have: New policy)
```

Before you apply, open one of your policies and turn on **Default policy**, or name one of them `Base`. To keep the Base behavior, create a policy with the three standard filters **AdGuard Base (ads & trackers)**, **AdGuard Malware** and **AdGuard Phishing URL Blocklist**.

## General

- **Name:** unique, and shown in reports, the query log and exception requests. It must start with a letter or digit and contain only letters, digits, spaces, hyphens and underscores. The page checks only for an empty or duplicate name ("Policy name must not be empty." and "Another policy already has this name."). The build rejects any other character with a type error that names the pattern `[A-Za-z0-9][A-Za-z0-9_ -]*`. Renaming the default policy keeps it the default.
- **Description:** free text for your own notes.
- **Priority:** a whole number, 0 by default. The help text reads "Tie-breaker within an assignment tier — higher wins." It doesn't make a policy win across tiers. See [Priority](/docs/access-policies/assignments/#priority).
- **Default policy:** the switch reads "Make this the default policy", or "This is the default policy" on the current default. The default applies to clients no other assignment matches. To move it, open the other policy and turn the switch on there; you can't turn it off on the current default.

## Categories

**UT Capitole categories** are curated domain blacklists maintained by Université Toulouse Capitole (the help text points to `dsi.ut-capitole.fr/blacklists`). The editor shows all 65 categories as switches, each with its official description. The router downloads each selected category from the `olbat/ut1-blacklists` mirror on GitHub as a plain domain list.

Every category you switch on is blocked. Some ids are French, and a few lists contain sites that are *suitable* rather than objectionable. For example, **child** is "Any website allowed to child (less than 10 years old)" and **liste_bu** is a French list of educational sites. Switching those on blocks those sites.

Categories schools and businesses often start with:

| Category | Description (from the editor) |
| --- | --- |
| `porn` | Pornographic sites (smaller, mirror-friendly alternative to 'adult'). |
| `mixed_adult` | Websites which contains adult sections unstructured |
| `gambling` | Gambling and games sites, casino, etc. |
| `dating` | Dating, matching site for single person |
| `drogue` | Sites relative to drugs. |
| `agressif` | Some aggressive sites. |
| `malware` | Any website which deliver malware |
| `phishing` | Phishing sites (same as malware category) |
| `cryptojacking` | Mining site by hijacking |
| `hacking` | Hacking sites. |
| `warez` | Warez sites. |
| `games` | Games sites (flash and online games) |
| `social_networks` | All social networks sites |
| `vpn` | VPN site |
| `doh` | Site which provides DNS over HTTP service |
| `redirector` | Some redirector sites, which are used to circumvent filtering. |

:::doc-note
Don't use the **adult** category. It is too large (about 50 MB) for the mirror the router downloads from. Use **mixed_adult** or **porn** instead.
:::

## Standard filters

**Standard filters** are well-known ad, tracker, malware and phishing lists, each behind one switch. The router knows each list's format and files it correctly.

| Switch label | JSON key | List | Blocks |
| --- | --- | --- | --- |
| **AdAway hosts list** | `adaway` | AdAway | Ads, mainly mobile |
| **AdGuard Base (ads & trackers)** | `adguard_ads` | AdGuard Base | Ads and trackers |
| **Dandelion Sprout Anti-Malware** | `adguard_anti_malware` | Dandelion Sprout's Anti-Malware List | Malware |
| **AdGuard Malware** | `adguard_malware` | AdGuard Malware URL Blocklist | Malware |
| **Big List of Hacked Malware Sites** | `adguard_hacked_sites` | Hacked Malware Web Sites | Compromised sites serving malware |
| **AdGuard Phishing URL Blocklist** | `adguard_phishing` | AdGuard Phishing URL Blocklist | Phishing |
| **Phishing Army (PhishTank + OpenPhish)** | `phishtank_openphish` | Phishing Army | Phishing |
| **Steven Black unified hosts** | `steven_black` | Steven Black's Hosts | Ads and malware |
| **Peter Lowe's ad/tracker list** | `yoyo_adservers` | Peter Lowe's Ad and tracker server list | Ads and trackers |

Ad and tracker lists occasionally break a site that depends on an ad or analytics domain. Use them on policies for general browsing, and consider leaving them off policies for servers and appliances.

## Custom lists

**Custom lists** adds lists you host or choose yourself. Each row is a list kind and a URL. To add one, pick the kind, paste the URL and click **Add list**. **Remove** deletes a row.

| Kind | JSON key | Expected format |
| --- | --- | --- |
| **Block list (hosts format)** | `blockListUrls` | A hosts file, or one domain per line |
| **Allow list** | `allowListUrls` | A hosts file, or one domain per line; these domains are always allowed |
| **AdBlock format** | `adblockListUrls` | AdGuard or Adblock Plus filter syntax |
| **Regex block list** | `regexBlockListUrls` | One regular expression per line |

In an AdBlock-format list, a rule such as `||example.com^` blocks a domain and `@@||example.com^` allows it. Advanced Blocking doesn't detect a list's syntax, so choose the kind that matches the file. A list filed under the wrong kind doesn't block what you expect. Lists are downloaded by the router and refreshed every 24 hours.

## Domains & regex

- **Allow domains:** domains that are always allowed, including their subdomains. An allow rule wins over every block in the policy, from any list or category.
- **Block domains:** domains to block, including their subdomains.
- **Allow regex** and **Block regex:** regular expressions matched against the queried name, case-insensitively. For example, `(^|\.)example\.net$` matches `example.net` and every name under it.

The router checks allow rules first: allowed domains, allow lists, allow regexes, and `@@` exceptions in AdBlock-format lists. Only if nothing allows a name does it check block domains, block lists, block regexes and AdBlock-format lists. An approved [exception request](/docs/access-policies/block-page/#handle-exception-requests) is added to **Allow domains**.

## Response

**Blocked-query response** chooses how the router answers a blocked query:

- **NXDOMAIN:** the name appears not to exist. Browsers show their own "can't reach this site" error, and the [block page](/docs/access-policies/block-page/) never appears. Use it for groups that should never see the page, such as servers, printers and other appliances.
- **Blocking address** (the default): the router answers with the addresses in **Blocking addresses**, `0.0.0.0` and `::` by default. The help text reads "A/AAAA answers for blocked queries. With the block page enabled, blockingAddress policies land clients on the block page."

While the block page is on, every **Blocking address** policy answers with the router's LAN gateway address instead, such as `192.168.1.1`, whatever **Blocking addresses** contains. The addresses you enter apply only while the block page is off.

For troubleshooting, every policy also answers a TXT query for a blocked name with a short report: the policy that blocked it and the list or rule that matched. See [Troubleshooting](/docs/access-policies/troubleshooting/#find-out-why-a-site-is-blocked).

## Assignments

The last section of the editor, **Assignments**, sets which clients get the policy: **Networks**, **Subnets (CIDR)**, **Host groups** and **Directory groups**. See [Assign policies](/docs/access-policies/assignments/).

## Worked example: a school

A school has a LAN on `192.168.1.0/24`, an Active Directory with `Students` and `Staff` groups, and a host group named `Library kiosks` on the Hosts page. Students and anything the router doesn't recognize should get strict filtering. Staff should get security filtering only.

1. Add a policy named `Students`. Turn on **Default policy**, so unregistered devices and visitors get the strict rules.
2. Under **Categories**, turn on `porn`, `mixed_adult`, `gambling`, `dating`, `games`, `social_networks`, `vpn`, `doh`, `redirector` and `warez`.
3. Under **Standard filters**, turn on **AdGuard Base (ads & trackers)**, **AdGuard Malware** and **AdGuard Phishing URL Blocklist**.
4. Under **Domains & regex**, add `khanacademy.org` to **Allow domains** so no category can block it.
5. Under **Assignments**, select `Library kiosks` in **Host groups** and type `Students` in **Directory groups**.
6. Add a second policy named `Staff` with **Priority** `10`. Turn on **AdGuard Malware**, **AdGuard Phishing URL Blocklist** and **Phishing Army (PhishTank + OpenPhish)**, and the `porn` and `mixed_adult` categories. Under **Directory groups**, type `Staff`.
7. Click **Save & apply**, then check a few devices on the **Preview** tab.

A teaching assistant who belongs to both `Students` and `Staff` gets **Staff**: both groups match at the directory tier, and Staff has the higher priority.

## In the settings file

The example above, in `/etc/nixos/router-settings.json`. Fields you leave out take their defaults, so a policy only needs the keys it uses. The `Library kiosks` group must exist under `hostGroups`, or the build fails:

```json
{
  "hostGroups": [
    { "name": "Library kiosks" }
  ],
  "accessPolicies": {
    "defaultPolicy": "Students",
    "policies": [
      {
        "name": "Students",
        "description": "Strict filtering for students and unrecognized devices",
        "priority": 0,
        "categories": ["porn", "mixed_adult", "gambling", "dating", "games", "social_networks", "vpn", "doh", "redirector", "warez"],
        "standardFilters": ["adguard_ads", "adguard_malware", "adguard_phishing"],
        "allowDomains": ["khanacademy.org"],
        "responseType": "blockingAddress",
        "assignments": {
          "hostGroups": ["Library kiosks"],
          "directoryGroups": ["Students"]
        }
      },
      {
        "name": "Staff",
        "description": "Security filtering only",
        "priority": 10,
        "categories": ["porn", "mixed_adult"],
        "standardFilters": ["adguard_malware", "adguard_phishing", "phishtank_openphish"],
        "responseType": "blockingAddress",
        "assignments": {
          "directoryGroups": ["Staff"]
        }
      }
    ]
  }
}
```

Every key a policy accepts, with its default:

| Key | Default | Notes |
| --- | --- | --- |
| `name` | (required) | Pattern `[A-Za-z0-9][A-Za-z0-9_ -]*`, unique |
| `description` | `""` | |
| `priority` | `0` | Higher wins within a tier |
| `categories` | `[]` | UT Capitole category ids |
| `standardFilters` | `[]` | Keys from the standard filters table |
| `blockListUrls`, `allowListUrls`, `adblockListUrls`, `regexBlockListUrls` | `[]` | Custom list URLs |
| `blockDomains`, `allowDomains` | `[]` | Include subdomains |
| `blockRegex`, `allowRegex` | `[]` | Regular expressions |
| `responseType` | `"blockingAddress"` | Or `"nxdomain"` |
| `blockingAddresses` | `["0.0.0.0", "::"]` | Ignored while the block page is on |
| `assignments` | all lists empty | `networks`, `subnets`, `hostGroups`, `directoryGroups` |

`defaultPolicy` defaults to `"Base"`. A category or standard filter key that doesn't exist fails the build with a type error that lists the accepted values.
