---
title: Block page and exceptions
description: Show users a branded page when a site is blocked, let them request an exception, and approve or deny requests in Cockpit.
code:
  - modules/access-policies.nix
  - modules/dns-technitium.nix
  - modules/firewall.nix
  - modules/reporting.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/router-dns-tools/router_dns_tools/logd.py
  - pkgs/router-dns-tools/router_dns_tools/blockpage/index.html
  - pkgs/cockpit-router/src/access-policies.tsx
---

# Block page and exceptions

The block page tells users that a site was blocked on purpose, instead of leaving them with a browser error. It includes a form to request an exception. Requests land on **Access Policies → Exception requests**, where you approve them into a policy's allow list or deny them.

## Before you start

- The page appears only for policies whose **Blocked-query response** is **Blocking address**, which is the default. Policies set to **NXDOMAIN** never show it. See [Response](/docs/access-policies/policies/#response).
- To approve requests from Cockpit, you need at least one policy of your own. The built-in Base policy that exists while you have no policies can't be chosen as a target.

## Turn on the block page

1. Open **Access Policies → DNS settings**.
2. Under **Block page**, turn on **Serve a block page**. The help text reads "Served on ports 80/443 for blocked domains; includes the exception-request form."
3. Set the text:
   - **Browser title:** the page title in the browser tab. Default "Website Blocked".
   - **Heading:** the large heading. Default "Website Blocked".
   - **Message:** the paragraph under the heading. Default "This website has been blocked by your network administrator."
   - **Contact email:** optional. When set, the page shows "Questions? Contact" followed by a mail link.
4. Click **Save & apply**.

Changing the page's text restarts the DNS server when you apply, so DNS pauses for a few seconds.

### In the settings file

```json
{
  "accessPolicies": {
    "blockPage": {
      "enable": true,
      "title": "Website Blocked",
      "heading": "This site is blocked at Example School",
      "message": "This website has been blocked by your network administrator.",
      "contactEmail": "helpdesk@example.org"
    }
  }
}
```

## What users see

The page shows your heading and message, then "Blocked address:" followed by the blocked domain, and the contact line if you set one. Under it, a collapsed **Request an exception** section holds a text box labeled "Why do you need access to this site?" and a **Send request** button.

After a user sends a request, they see "Request submitted" and the message "Your request to unblock *domain* has been sent to your network administrator."

## HTTPS sites show a certificate warning

Almost every site is HTTPS. The browser connects to the router expecting the real site's certificate, and the block page can only offer its own self-signed certificate, issued to the router's DNS name. The browser shows a certificate error instead of the page:

- For most sites, the user sees the browser's warning and can click through to reach the block page.
- For sites that use HSTS, which includes most large sites, the browser offers no way past the warning, so the user never sees the block page.
- Requests to plain `http://` addresses show the page directly.

The router has no setting that avoids this. Tell users that a certificate warning on a site they expected to work usually means it is blocked.

## How it works

- **The answer points at the router.** While the block page is on, every **Blocking address** policy answers blocked queries with the router's LAN gateway address, such as `192.168.1.1`, for clients on every network. The policy's own **Blocking addresses** are ignored.
- **The page is served on ports 80 and 443.** Technitium's Block Page app listens on all router addresses, but the firewall keeps it off the WAN. It allows everything from the LAN and WireGuard, and opens 80, 443 and the exception form's port to the guest network only while the block page is on. The page's text comes from your settings, HTML-escaped, and is rebuilt on each apply.
- **The page reads the domain from the address bar.** The browser asked for `http://blocked.example.com/` and reached the router, so the page shows `blocked.example.com` as the blocked address and sends it with the form.
- **Requests go to router-logd.** The form posts to `http://192.168.1.1:8067/portal/request-exception`, using your LAN gateway address and the `reporting.logd.port` setting (8067 by default). `router-logd` records the time, domain, client address and reason. From the client address it also works out the device name, its user and host group, and the policy that applies, so you can see who asked.
- **Requests are rate-limited.** Each client address can send 10 requests per hour; after that it gets "Too many requests". The domain must contain only letters, digits, dots and hyphens, and the reason is cut to 1,000 characters.

## Handle exception requests

**Access Policies → Exception requests** lists the latest 500 requests. When requests are waiting, the tab label shows the count, such as **Exception requests (3)**. Click **Refresh** to reload the list.

| Column | Shows |
| --- | --- |
| **Time** | When the request was sent |
| **Domain** | The blocked domain |
| **Requested by** | The device name, or the user, or the client address, with the address underneath (and the user too, when both are known) |
| **Group** | The device's host group |
| **Policy** | The policy that applied to the client |
| **Reason** | The user's explanation; hover to read it all |
| **Status** | `pending`, `approved` or `denied` |

To approve a request:

1. Click **Approve** on its row. The **Approve exception for** *domain* card opens.
2. Under **Add allow rule to policy**, choose the policy to change. It starts on the policy that blocked the request, when that policy still exists. The help text reads "The domain is appended to the policy's allow-domains list."
3. Click **Approve**. The page confirms "*domain* allowed in policy "*name*" — apply the change from the tray to activate it."
4. In the changes tray at the top of the page, click **Apply**.

To refuse a request, click **Deny**. That only marks it denied; nothing changes in your policies.

Keep in mind:

- **An approval applies to everyone on that policy**, not only to the person who asked. To allow a site for one group only, create a separate policy for that group.
- **The domain is allowed with its subdomains**, but nothing else. Many sites also load from other domains, such as a CDN, that may still be blocked. Check the [query log](/docs/access-policies/reports/#query-log) with **Blocked only** on to find them, and add them to **Allow domains** in the policy editor.
- **Approving doesn't notify the user.** Tell them when the change is applied.

## Limits

- The block page never appears for **NXDOMAIN** policies.
- HTTPS sites show a certificate warning first, and HSTS sites never show the page.
- The page only appears when the blocked name is opened in a browser. Apps and background requests fail to connect.
- The form requires the block page, so users on NXDOMAIN policies can't send requests.
- With the [reverse proxy](/docs/ingress/reverse-proxy/) on, guest and WireGuard clients don't see the block page: their connections to the LAN gateway on 80 and 443 go to the proxy. See [Ports and services](/docs/reference/ports/#redirected-and-blocked-traffic).

## Troubleshooting

- **The page never appears, even for plain HTTP sites.** Check that the client's policy uses **Blocking address**, and that **Serve a block page** is on and applied. Check that the Block Page app bound its ports:

  ```bash
  sudo sh -c 'grep -h "Web server" /var/lib/technitium-dns-server/logs/*.log | tail -n 4'
  ```

  Expect lines containing `was bound successfully` for ports 80 and 443. `failed to bind` means another service holds the port.
- **Sending a request fails.** The form posts to port 8067 on the LAN gateway address. Check that `router-logd` is running with `systemctl status router-logd`.
- **Exception requests shows "Could not reach router-logd".** Same cause: `router-logd` is stopped or failing. See [Troubleshooting](/docs/access-policies/troubleshooting/).
- **Approve is disabled.** The **Add allow rule to policy** list is empty because no policies are defined. Create a policy first.
