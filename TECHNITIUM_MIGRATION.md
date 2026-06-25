# Technitium DNS Server Migration Guide

## Overview

The NixOS Router module now supports both **AdGuard Home** and **Technitium DNS Server** as DNS filtering backends. Technitium provides enterprise-grade features that address AdGuard's limitations for business and school deployments.

## Quick Start

### Using AdGuard Home (Default)
```nix
router = {
  dns = {
    adguard.enable = true;
    # ... existing AdGuard configuration
  };
};
```

### Migrating to Technitium DNS Server
```nix
router = {
  dns = {
    adguard.enable = false;  # Disable AdGuard
    technitium.enable = true;  # Enable Technitium
    
    technitium = {
      adminPasswordHash = "your-hash-here";  # Generate with: technitium-dns-server hash
      enableRbac = true;  # Enable multi-user administration
      enableGroupPolicies = true;  # Enable network-based group policies
      
      # Block lists (same URLs as AdGuard)
      blockLists = [
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"
      ];
    };
  };
};
```

## Configuration Reference

### Shared Options

Both backends support these common options:

```nix
router.dns = {
  # Upstream DoH servers
  upstreamServers = [
    "https://dns.cloudflare.com/dns-query"
    "https://dns.google/dns-query"
  ];

  # SafeSearch enforcement
  safeSearch = true;
};
```

### AdGuard Home Options

```nix
router.dns.adguard = {
  enable = true;
  listenPort = 53;
  webPort = 3000;
  
  # Standard filters
  standardFilters = {
    adguard_ads = true;
    adguard_malware = true;
    # ... more filters
  };
  
  # Custom filters
  extraFilters = [ ... ];
  
  # Allow/block lists
  allowList = [ "example.com" ];
  blockList = [ "ads.example.com" ];
};
```

### Technitium DNS Server Options

```nix
router.dns.technitium = {
  enable = true;
  
  # Basic configuration
  package = pkgs.technitium-dns-server;  # Uses existing nixpkgs package
  webPort = 5380;
  adminPasswordHash = "your-hash-here";
  
  # Block lists (same format as AdGuard)
  blockLists = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"
  ];
  
  allowLists = [ "example.com" ];
  
  # Guest network additional blocking
  guestBlockLists = [
    "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/porn/domains"
  ];
  
  # Advanced features
  enableRbac = true;  # Multi-user administration
  enableGroupPolicies = true;  # Network-based group policies
  enableSso = false;  # SSO integration (optional)
  
  blockDoHProviders = true;  # Prevent DNS bypass
  
  # SSO configuration (if enableSso = true)
  ssoAuthority = "https://auth.example.com";
  ssoClientId = "your-client-id";
  ssoClientSecret = "your-client-secret";
};
```

## Key Advantages of Technitium

### 1. Multi-User Administration
```nix
# Technitium supports multiple admin users with RBAC
enableRbac = true;

# Create users via Technitium web UI or API:
# - Administrators: Full access
# - DNS-Administrators: DNS management only
# - Everyone: Read-only access
```

### 2. Network-Based Group Policies
```nix
# Different filtering policies per network
enableGroupPolicies = true;

# Automatically configured for:
# - LAN network (192.168.1.0/24) → "lan" group
# - Guest network (192.168.2.0/24) → "guest" group

# Each group has:
# - Separate block lists
# - Different filtering rules
# - Independent policies
```

### 3. Advanced Blocking Features
- **Regex pattern matching** for sophisticated filtering
- **AdBlock format** support
- **Multiple block list types**: domain lists, regex, AdBlock
- **Per-group policies** with different blocking behaviors
- **Allow/block lists with URL patterns**

### 4. Better Enterprise Integration
- **SSO with OpenID Connect** for enterprise authentication
- **HTTP API** for automation and integration
- **Role-based access control** with granular permissions
- **Clustering support** for high availability

### 5. Enhanced Statistics and Logging
- **Per-client statistics** with detailed breakdowns
- **Query logging** with configurable retention
- **Network-based reporting** by groups
- **Real-time monitoring** via web UI

## Migration Steps

### 1. Generate Admin Password Hash
```bash
# Generate password hash for Technitium admin
nix run nixpkgs#technitium-dns-server hash
# Enter password when prompted, copy the resulting hash
```

### 2. Update Router Configuration
```nix
router = {
  dns = {
    adguard.enable = false;
    technitium = {
      enable = true;
      adminPasswordHash = "your-generated-hash-here";
      
      # Copy block lists from AdGuard configuration
      blockLists = [
        # ... your existing block lists
      ];
      
      # Enable advanced features
      enableRbac = true;
      enableGroupPolicies = true;
    };
  };
};
```

### 3. Apply Configuration
```bash
# Rebuild NixOS configuration
sudo nixos-rebuild switch

# Verify Technitium is running
sudo systemctl status technitium-dns-server

# Access web UI
# http://router-ip:5380
```

### 4. Configure Users and Groups (Optional)
```bash
# Access Technitium web UI at http://router-ip:5380
# Log in with admin user (password from step 1)

# Create additional users:
# - Navigate to Administration > Users
# - Add users with appropriate group memberships

# Configure group policies:
# - Navigate to Apps > Advanced Blocking App
# - Adjust group configurations as needed
```

## Configuration Compatibility

### Block Lists
Most AdGuard block lists work directly with Technitium:

**AdGuard Format:**
```nix
# AdGuard uses filter objects
standardFilters = [
  { name = "AdGuard Base"; url = "..."; id = 1; enabled = true; }
];
```

**Technitium Format:**
```nix
# Technitium uses direct URLs
blockLists = [
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
];
```

### SafeSearch
Both support SafeSearch enforcement:

```nix
# Works in both backends
dns.safeSearch = true;
```

### User Rules
AdGuard user rules need minor format conversion:

**AdGuard:**
```nix
user_rules = [
  "||domain^"  # Block
  "@@||domain^"  # Allow
];
```

**Technitium:**
```nix
# Use allowLists and blockLists instead
allowLists = [ "domain" ];
blockLists = [ "domain" ];
```

## Cockpit Integration

The Cockpit router plugin can be adapted to work with Technitium:

### API Differences

**AdGuard API:**
```
GET http://127.0.0.1:3000/control/stats
GET http://127.0.0.1:3000/control/querylog
```

**Technitium API:**
```
GET http://127.0.0.1:5380/api/dashboard/stats/get
GET http://127.0.0.1:5380/api/logs/entries/get
```

### Migration Path

1. Update Cockpit plugin to detect backend type
2. Adapt API calls based on selected backend
3. Implement Technitium-specific features (RBAC, group policies)
4. Provide unified interface for both backends

## Troubleshooting

### Port Conflicts
If you see port conflicts:
```bash
# Check what's using port 53
sudo ss -tulnp | grep :53

# Ensure systemd-resolved is disabled
sudo systemctl disable systemd-resolved
```

### Configuration Issues
```bash
# Check Technitium logs
sudo journalctl -u technitium-dns-server -f

# Verify configuration file
sudo cat /etc/technitium-dns-server/dnsconfig.txt
```

### Performance Issues
```bash
# Monitor Technitium performance
sudo systemctl status technitium-dns-server
sudo journalctl -u technitium-dns-server --since "1 hour ago"

# Check DNS queries
curl http://localhost:5380/api/dashboard/stats/get
```

## Advanced Configuration

### Custom Block Lists
```nix
technitium = {
  blockLists = [
    # Standard block lists
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    
    # Custom block lists
    "https://example.com/custom-blocklist.txt"
    
    # UT Capitole categories
    "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/malware/domains"
  ];
};
```

### SSO Integration
```nix
technitium = {
  enableSso = true;
  ssoAuthority = "https://auth.example.com";
  ssoClientId = "router-dns";
  ssoClientSecret = "your-secret";
  
  # Auto-create users from SSO
  # Users will be added to "Everyone" group by default
};
```

### High Availability Clustering
```nix
# Technitium supports clustering (configure via web UI)
# 1. Install Technitium on multiple nodes
# 2. Configure cluster via web UI
# 3. Set up primary-secondary relationships
# 4. Configure automatic failover

# Example cluster setup:
# - Primary router: 192.168.1.1
# - Secondary router: 192.168.1.2
# - Shared storage for configuration sync
```

## Performance Comparison

### AdGuard Home
- **Memory**: ~100-200MB
- **CPU**: Low single-core usage
- **Query Processing**: ~10,000 QPS
- **Scaling**: Single instance, limited horizontal scaling

### Technitium DNS Server
- **Memory**: ~150-300MB (with advanced features)
- **CPU**: Efficient multi-core usage
- **Query Processing**: ~50,000+ QPS
- **Scaling**: Supports clustering and horizontal scaling

## Security Considerations

### Both Backends
- DoH provider blocking to prevent DNS bypass
- Query logging for audit trails
- TLS encryption for web UI
- Rate limiting and abuse prevention

### Technitium Additional Security
- **Multi-user authentication** reduces shared credential risks
- **RBAC** provides principle of least privilege
- **SSO integration** for centralized identity management
- **Enhanced audit logging** with user attribution
- **Session management** with configurable timeouts

## Support and Resources

### AdGuard Home
- **Documentation**: https://github.com/AdguardTeam/AdGuardHome/wiki
- **Community**: https://reddit.com/r/AdGuardHome
- **Source**: https://github.com/AdguardTeam/AdGuardHome

### Technitium DNS Server
- **Documentation**: https://technitium.com/dns/
- **API Docs**: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
- **Community**: https://reddit.com/r/technitium
- **Source**: https://github.com/TechnitiumSoftware/DnsServer

## Conclusion

**Migrating to Technitium DNS Server** provides enterprise-grade DNS filtering with multi-user support, group-based policies, and better scalability for business and school environments. The migration is straightforward, with most AdGuard configurations directly compatible.

**Key Benefits:**
- ✅ Multi-user administration with RBAC
- ✅ Network-based group policies
- ✅ Advanced blocking features
- ✅ Better enterprise integration
- ✅ Enhanced statistics and logging
- ✅ Clustering support for high availability
- ✅ SSO integration for enterprise authentication

**When to Use Each Backend:**
- **AdGuard Home**: Small deployments, simple use cases, minimal administration
- **Technitium**: Business/school environments, multi-user access, complex policies, enterprise integration