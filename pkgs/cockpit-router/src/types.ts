// Shared TypeScript shapes for the new settings sections (mirroring the
// generated router-settings.schema.json) and the runtime state files/APIs
// (directory sync, router-logd). interfaces.ts keeps the NIC/topology logic —
// these are the access-protection domain types.

// ── Settings sections (router-settings.json) ────────────────────────────────
export interface RouterHost {
  mac: string;
  name: string;
  staticIp?: string | null;
  network?: "lan" | "guest";
  group?: string | null;
  user?: string | null;
  // IPv6 interface identifier (low 64 bits, e.g. "::42"): the delegated prefix
  // is dynamic, so IPv6 port forwards and AAAA records identify the device by
  // this alone.
  ipv6Suffix?: string | null;
  // Public DNS name router.ddns keeps pointed at the device.
  publicHostname?: string | null;
  notes?: string;
}

// router.portForwards[] — `host` names a RouterHost. IPv4 DNATs to its
// staticIp, IPv6 opens a pinhole to its own address (ipv6Suffix).
export interface PortForward {
  name?: string;
  protocol?: "tcp" | "udp";
  host: string;
  family?: "both" | "ipv4" | "ipv6";
  ports: number[];
  sources?: string[];
}

export interface DdnsSettings {
  enable?: boolean;
  cloudflare?: { apiTokenFile?: string | null };
  names?: string[];
  ipv4?: boolean;
  ipv6?: boolean;
  intervalMinutes?: number;
  ttl?: number;
  proxied?: boolean;
}

// router.acme — account settings for the reverse proxy's certificates.
export interface AcmeSettings {
  email?: string;
  acceptTerms?: boolean;
  staging?: boolean;
  defaultChallenge?: "dns-cloudflare" | "http";
  cloudflare?: { apiTokenFile?: string | null };
}

export type AcmeChallenge = "default" | "dns-cloudflare" | "http";

// router.reverseProxy.routes[] — public hostnames proxied to a RouterHost's
// staticIp, all covered by one certificate named after the first hostname.
export interface ProxyRoute {
  name?: string;
  hostnames: string[];
  host: string;
  port?: number;
  scheme?: "http" | "https";
  tlsVerify?: boolean;
  challenge?: AcmeChallenge;
  hsts?: boolean;
}

export interface ReverseProxySettings {
  enable?: boolean;
  publishDns?: boolean;
  routes?: ProxyRoute[];
}

// router.cloudflareTunnel.ingress[] — a public name served through the
// router's Cloudflare Tunnel to a RouterHost's staticIp.
export interface TunnelIngress {
  hostname: string;
  host: string;
  port?: number;
  scheme?: "http" | "https";
  noTLSVerify?: boolean;
  httpHostHeader?: string;
}

export interface CloudflareTunnelSettings {
  enable?: boolean;
  apiTokenFile?: string | null;
  ingress?: TunnelIngress[];
}

export interface HostGroup {
  name: string;
  description?: string;
}

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "ANAME" | "TXT" | "SRV";

export interface DnsOverride {
  name: string;
  type?: DnsRecordType;
  value: string;
  ttl?: number;
  notes?: string;
}

export interface DnsForwardZone {
  zone: string;
  forwarders: string[];
  protocol?: "Udp" | "Tcp" | "Tls" | "Https" | "Quic";
  dnssecValidation?: boolean;
  notes?: string;
}

export interface PolicyAssignments {
  networks?: ("lan" | "guest" | "wireguard")[];
  subnets?: string[];
  hostGroups?: string[];
  directoryGroups?: string[];
}

export interface AccessPolicy {
  name: string;
  description?: string;
  priority?: number;
  categories?: string[];
  standardFilters?: string[];
  blockListUrls?: string[];
  allowListUrls?: string[];
  adblockListUrls?: string[];
  regexBlockListUrls?: string[];
  blockDomains?: string[];
  allowDomains?: string[];
  blockRegex?: string[];
  allowRegex?: string[];
  responseType?: "nxdomain" | "blockingAddress";
  blockingAddresses?: string[];
  assignments?: PolicyAssignments;
}

export interface BlockPageSettings {
  enable?: boolean;
  title?: string;
  heading?: string;
  message?: string;
  contactEmail?: string;
}

export interface AccessPoliciesSection {
  defaultPolicy?: string;
  policies?: AccessPolicy[];
  blockPage?: BlockPageSettings;
}

export interface DirectorySettings {
  provider?: "none" | "sssd";
  syncIntervalMinutes?: number;
  sssd?: {
    domain?: string;
    servers?: string[];
    baseDn?: string;
    userSearchBase?: string;
    groupSearchBase?: string;
    schema?: "ad" | "rfc2307bis" | "rfc2307";
    idMapping?: boolean;
    bindDn?: string;
    bindPasswordFile?: string | null;
    tlsCaCertFile?: string | null;
    tlsClientCertFile?: string | null;
    tlsClientKeyFile?: string | null;
    tlsReqCert?: "never" | "allow" | "try" | "demand" | "hard";
    cacheTimeoutMinutes?: number;
    groups?: string[];
    adminGroup?: string;
    adminSsh?: boolean;
  };
}

export interface ReportSchedule {
  name: string;
  frequency?: "daily" | "weekly" | "monthly";
  dayOfWeek?: "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun";
  time?: string;
  recipients?: string[];
  sections?: ("overview" | "topDomains" | "topBlocked" | "perGroup" | "perDevice" | "perUser")[];
  groups?: string[];
}

export interface ReportingSettings {
  enable?: boolean;
  retentionDays?: number;
  logd?: { port?: number };
  schedules?: ReportSchedule[];
  email?: { accountId?: string; apiTokenFile?: string | null; fromAddress?: string };
}

// ── Directory sync state files (read-only runtime data) ─────────────────────
export interface DirectoryUser {
  id: string; // POSIX login name — what router.hosts[].user must hold
  name: string; // GECOS full name
  email: string; // "" for POSIX, or the alias hosts[].user used if NSS canonicalized it
  groups: string[]; // POSIX group names (group.id === group.name)
}

export interface DirectoryGroup {
  id: string;
  name: string;
}

export interface DirectoryState {
  users: DirectoryUser[];
  groups: DirectoryGroup[];
  syncedAt?: string;
}

export interface DirectoryStatus {
  lastSync?: string;
  ok?: boolean;
  error?: string | null;
  // Referenced names NSS could not resolve. NOT a sync failure — a typo must
  // not blank the user tier for everyone else (see directory_sync/__init__.py).
  unresolved?: string[];
}

// ── Dynamic DNS status (router-ddns status.json, read-only) ─────────────────
export interface DdnsRecordStatus {
  name: string;
  // CNAME rows appear when a name is dropped: one per record replaced to take
  // it over, restored or left out (the detail says why).
  type: "A" | "AAAA" | "CNAME";
  host?: string | null; // set for a host's publicHostname, absent for router names
  content: string | null;
  state: "created" | "updated" | "unchanged" | "skipped" | "removed" | "error";
  detail?: string;
}

export interface DdnsStatus {
  lastRun?: string;
  ok?: boolean;
  error?: string | null;
  addresses?: { ipv4?: string | null; ipv4Source?: string; ipv6?: string | null };
  records?: DdnsRecordStatus[];
  // Set when a disabled run kept records from before the upgrade, when
  // turning dynamic DNS off left them: what to do to delete them.
  message?: string;
}

// ── Cloudflare Tunnel status (router-cloudflare-tunnel status.json) ───────
export interface TunnelConnection {
  colo: string;
  originIp: string;
  openedAt: string;
  clientVersion: string;
}

export interface TunnelStatus {
  updated?: string;
  ok?: boolean;
  error?: string | null;
  tunnel?: { id: string; name: string; status: string } | null;
  // Set while there are no hostnames and no tunnel yet: why there is none.
  message?: string;
  connections?: TunnelConnection[];
  records?: Record<string, { ok: boolean; message: string }>;
}

// ── router-logd API shapes ───────────────────────────────────────────────────
export interface LogEntry {
  ts: string;
  client_ip: string;
  protocol: string;
  response_type: string;
  rcode: string;
  qname: string;
  qtype: string;
  answer: string;
  device: string | null;
  host_group: string | null;
  policy: string | null;
}

export interface LogPage {
  total: number;
  page: number;
  pageSize: number;
  entries: LogEntry[];
}

export interface TopEntry {
  name: string;
  hits: number;
  blocked: number;
}

export interface LogSummary {
  total: number;
  blocked: number;
  clients: number;
}

export interface ExceptionRequest {
  id: number;
  ts: string;
  domain: string;
  client_ip: string;
  device: string | null;
  user: string | null;
  host_group: string | null;
  policy: string | null;
  reason: string;
  status: "pending" | "approved" | "denied";
}

// ── Technitium dashboard API shapes (subset the UI consumes) ─────────────────
export interface TechnitiumStats {
  totalQueries: number;
  totalNoError: number;
  totalServerFailure: number;
  totalNxDomain: number;
  totalRefused: number;
  totalAuthoritative: number;
  totalRecursive: number;
  totalCached: number;
  totalBlocked: number;
  totalDropped: number;
  totalClients: number;
  zones: number;
  cachedEntries: number;
  allowedZones: number;
  blockedZones: number;
  allowListZones: number;
  blockListZones: number;
}

export interface TechnitiumChartDataset {
  label: string;
  data: number[];
}

export interface TechnitiumMainChartData {
  labelFormat: string;
  labels: string[]; // ISO timestamps
  datasets: TechnitiumChartDataset[];
}

export interface TechnitiumDashboard {
  stats: TechnitiumStats;
  mainChartData: TechnitiumMainChartData;
}

export interface TechnitiumTopEntry {
  name: string;
  domain?: string;
  hits: number;
}

export type StatsRange = "LastHour" | "LastDay" | "LastWeek" | "LastMonth";
