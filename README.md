# STM32 - SPDM demo

Embassy based SPDM (Security Protocols and Data Models) demo applications running on STM32.

This repo implements both a SPDM responder and a SPDM requester.

Currently the responder is running on a STM32U5A5 and the requester on a STM32H753.
Porting it for a different STM32 is usually no big deal though.

The crates are intentionally not in a Cargo workspace since rust-analyzer gets confused due to conflicting feature flags otherwise.
