---
title: Reference
description: Lookup pages for nixos-router, covering Cloudflare API tokens, ports and services, the settings file and its JSON schema.
order: 8
code:
  - pkgs/cockpit-router/src/router-settings.schema.json
---

# Reference

These pages collect details that several features share. Use them to look something up rather than to follow a task from start to finish.

- [Cloudflare API tokens](cloudflare-tokens.md): the permissions each Cloudflare feature needs, the default token files, and how to create, store, rotate and remove tokens.
- [Ports and services](ports.md): the ports the router listens on and the services behind them.
- [The settings file](../start/settings-file.md): `/etc/nixos/router-settings.json`, the file the Cockpit settings pages read and write.

## Settings schema

Every key the settings file accepts, with its type, default and description, is listed in the JSON Schema at `pkgs/cockpit-router/src/router-settings.schema.json` in the repository. It's generated from the router's NixOS options, and Cockpit checks the settings file against it before it applies a change.
