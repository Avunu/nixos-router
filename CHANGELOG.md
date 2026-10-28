# Changelog

## [0.2.2](https://github.com/Avunu/nixos-router/compare/v0.2.1...v0.2.2) (2026-10-28)


### Bug Fixes

* router-dns-tools project ([#96](https://github.com/Avunu/nixos-router/issues/96)) ([6084e3a](https://github.com/Avunu/nixos-router/commit/6084e3a39b40f83da15516c8b26d0e48e556db7b))

## [0.2.1](https://github.com/Avunu/nixos-router/compare/v0.2.0...v0.2.1) (2026-10-28)


### Bug Fixes

* bump nixpkgs to 31ecbac and keep containers connected across firewall reloads ([#98](https://github.com/Avunu/nixos-router/issues/98)) ([aba984b](https://github.com/Avunu/nixos-router/commit/aba984b59ec28fb00710218ab9501defcaf37cf1))

## [0.2.0](https://github.com/Avunu/nixos-router/compare/v0.1.0...v0.2.0) (2026-10-28)


### Features

* **access-policies:** set SafeSearch per policy and per site ([#95](https://github.com/Avunu/nixos-router/issues/95)) ([292c426](https://github.com/Avunu/nixos-router/commit/292c426f99453fadbe6d9098fb780577c4d1d75d))
* **dns:** build the Technitium DNS Server from source, without its web console ([#86](https://github.com/Avunu/nixos-router/issues/86)) ([516caa0](https://github.com/Avunu/nixos-router/commit/516caa09a9fd0853124b3f0d435267322ace1b7b))


### Bug Fixes

* **avahi:** migrate to the RFC 42 settings options ([#83](https://github.com/Avunu/nixos-router/issues/83)) ([8a368ec](https://github.com/Avunu/nixos-router/commit/8a368ec04073274113e4f8e595d380babddb4be2))
* **deps-dev:** bump the npm group in /pkgs/cockpit-router with 2 updates ([#92](https://github.com/Avunu/nixos-router/issues/92)) ([e19388a](https://github.com/Avunu/nixos-router/commit/e19388af1d89269ad0254c61c4a2f2a1cc20a5fa))
* **deps-dev:** bump the npm group in /pkgs/cockpit-router with 3 updates ([#63](https://github.com/Avunu/nixos-router/issues/63)) ([3393675](https://github.com/Avunu/nixos-router/commit/33936759eb9a920a5cdcd5d44e4f44e22641980f))
* **deps:** bump arc-swap from 1.9.2 to 1.9.3 in /pkgs/router-proxy in the cargo group ([#90](https://github.com/Avunu/nixos-router/issues/90)) ([c94b035](https://github.com/Avunu/nixos-router/commit/c94b035e36bcc1a905981e496c0fbff46fe7dbf6))
* **deps:** bump arc-swap in /pkgs/router-proxy in the cargo group ([c94b035](https://github.com/Avunu/nixos-router/commit/c94b035e36bcc1a905981e496c0fbff46fe7dbf6))
* **deps:** bump disko from `61c844e` to `cedd626` ([#89](https://github.com/Avunu/nixos-router/issues/89)) ([1755df6](https://github.com/Avunu/nixos-router/commit/1755df62824a0ecb0b68bd39b42f29a1dea737d9))
* **deps:** bump disko from `725ea35` to `61c844e` ([#84](https://github.com/Avunu/nixos-router/issues/84)) ([565f4ce](https://github.com/Avunu/nixos-router/commit/565f4cea36a1a2cf650bbf04b088836be570e1d2))
* **deps:** bump git-hooks from `a0e4241` to `1ba1dbf` ([#73](https://github.com/Avunu/nixos-router/issues/73)) ([0dff438](https://github.com/Avunu/nixos-router/commit/0dff438fa19ff5093e64677dd61b0b2086a12474))
* **deps:** bump libc ([e11073d](https://github.com/Avunu/nixos-router/commit/e11073dc299bc6572129d60e2d854a2368b598b4))
* **deps:** bump libc from 0.2.190 to 0.2.191 in /pkgs/router-proxy in the cargo group across 1 directory ([#80](https://github.com/Avunu/nixos-router/issues/80)) ([e11073d](https://github.com/Avunu/nixos-router/commit/e11073dc299bc6572129d60e2d854a2368b598b4))
* **deps:** bump nixos-install-helper from `8563579` to `c9e5656` ([#88](https://github.com/Avunu/nixos-router/issues/88)) ([75513d2](https://github.com/Avunu/nixos-router/commit/75513d232e563dee644001a800a34a9a260b6b17))
* **deps:** bump nixos-install-helper from `c600ccb` to `8563579` ([#77](https://github.com/Avunu/nixos-router/issues/77)) ([ee1cec1](https://github.com/Avunu/nixos-router/commit/ee1cec19e04292b5000b05bc7f19491efb55c32b))
* **deps:** bump nixpkgs from `02c087f` to `3ec6363` ([#94](https://github.com/Avunu/nixos-router/issues/94)) ([530d80c](https://github.com/Avunu/nixos-router/commit/530d80c731e6c5de27e98c8fad8497ad047b6be8))
* **deps:** bump nixpkgs from `6510408` to `55bfb4d` ([#76](https://github.com/Avunu/nixos-router/issues/76)) ([1c96d28](https://github.com/Avunu/nixos-router/commit/1c96d28bbcdd867e1ede4dcdfb79d4b61bf0b8ce))
* **deps:** bump nixpkgs from `e7439b6` to `6510408` in the nix group ([#60](https://github.com/Avunu/nixos-router/issues/60)) ([67b2fc5](https://github.com/Avunu/nixos-router/commit/67b2fc5ecf6351ae0e51562960a0933cbe8d9f73))
* **deps:** bump the cargo group in /pkgs/router-proxy with 2 updates ([#74](https://github.com/Avunu/nixos-router/issues/74)) ([8108ec3](https://github.com/Avunu/nixos-router/commit/8108ec36c48bf3e2ba70911dbbd81be77513f5c4))
* **deps:** bump the npm group across 1 directory with 11 updates ([#82](https://github.com/Avunu/nixos-router/issues/82)) ([41d10af](https://github.com/Avunu/nixos-router/commit/41d10aff5eb1e9c23b4369f627533dda8237bf16))
* **deps:** bump tokio from 1.53.1 to 1.53.2 in /pkgs/router-proxy in the cargo group ([#62](https://github.com/Avunu/nixos-router/issues/62)) ([5fe1234](https://github.com/Avunu/nixos-router/commit/5fe12346ba1329e173b714d7c84ab801295de2a7))
* **deps:** bump tokio in /pkgs/router-proxy in the cargo group ([5fe1234](https://github.com/Avunu/nixos-router/commit/5fe12346ba1329e173b714d7c84ab801295de2a7))
* **dns:** give Cockpit a Technitium token that is really read-only ([#87](https://github.com/Avunu/nixos-router/issues/87)) ([92fa977](https://github.com/Avunu/nixos-router/commit/92fa977c870aa61c6efafe1ff46f23058e645740))
* **router-dns-tools:** pass makeWrapper args as separate list elements ([#69](https://github.com/Avunu/nixos-router/issues/69)) ([941f7be](https://github.com/Avunu/nixos-router/commit/941f7be43e62e976b9445c60bb40cd14835b4600))


### Documentation

* move the docs to the shared Avunu documentation site ([#91](https://github.com/Avunu/nixos-router/issues/91)) ([17942ff](https://github.com/Avunu/nixos-router/commit/17942ffaeb0c055861f7fe9e367336f344bed51f))
