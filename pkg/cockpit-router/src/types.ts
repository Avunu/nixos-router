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
  notes?: string;
}

export interface HostGroup {
  name: string;
  description?: string;
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
