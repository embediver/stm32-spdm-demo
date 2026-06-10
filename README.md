# STM32 - SPDM demo

Embassy based SPDM (Security Protocols and Data Models) demo applications running on STM32.

This repo implements both a SPDM responder and a SPDM requester.

Currently the responder is running on a STM32U5A5 and the requester on a STM32H753.
Porting it for a different STM32 is usually no big deal though.

The crates are intentionally not in a Cargo workspace since rust-analyzer gets confused due to conflicting feature flags otherwise.

## Features

Currently implemented is the following SPDM message flow:
- VCA stage
- Get digests
- Get certificates
- Challenge - response

The platform abstractions are in parts still only a mock an not fully featured.
Signature and certificate chain verification on the requester is still missing.

