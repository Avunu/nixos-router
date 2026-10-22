// Which navigation errors are worth asking the router about.
//
// A blocked HTTPS site fails in the browser because the router answers its
// name with the LAN gateway, whose Block Page app presents a certificate for
// the router, not for the site: a certificate or TLS error, or — if the Block
// Page app is off or firewalled — a refused, reset or timed-out connection.
// Anything else (a DNS failure, an abort, a download, a site's own 404) cannot
// be the router's block and is not sent anywhere.
//
// Chromium reports a `net::ERR_*` name, which is precise. Firefox reports
// "Error code <decimal nsresult>" or localized prose, which is not — so on
// Firefox every error except an abort is checked; the router's answer is what
// decides, and a not-blocked answer is cached.

const CHROMIUM_PREFIXES = ["net::ERR_CERT_", "net::ERR_SSL_", "net::ERR_ECH_"];

const CHROMIUM_EXACT = new Set([
  "net::ERR_CONNECTION_REFUSED",
  "net::ERR_CONNECTION_RESET",
  "net::ERR_CONNECTION_CLOSED",
  "net::ERR_CONNECTION_TIMED_OUT",
  "net::ERR_TIMED_OUT",
  "net::ERR_ADDRESS_INVALID",
  "net::ERR_ADDRESS_UNREACHABLE",
  "net::ERR_EMPTY_RESPONSE",
]);

/**
 * Firefox's aborts: NS_BINDING_ABORTED (0x804B0002) is a user stop or a
 * navigation that replaced this one; NS_ERROR_ABORT (0x80004004) is the
 * generic abort. Matched as decimal codes and by name.
 */
const FIREFOX_ABORTS = ["2152398850", "NS_BINDING_ABORTED", "2147500036", "NS_ERROR_ABORT"];

/** Whether a webNavigation.onErrorOccurred `error` string warrants a router check. */
export function shouldCheck(error: string | undefined): boolean {
  if (error === undefined || error === "") {
    return true;
  }
  if (error.startsWith("net::ERR_")) {
    return (
      CHROMIUM_PREFIXES.some((prefix) => error.startsWith(prefix)) || CHROMIUM_EXACT.has(error)
    );
  }
  return !FIREFOX_ABORTS.some((abort) => error.includes(abort));
}
