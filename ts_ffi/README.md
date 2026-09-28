# ts_ffi

C bindings to `tailscale-rs`.

`tailscale.h` is automatically generated in this directory when you `cargo build`. The library name
is `tailscalers` (`../target/*/libtailscalers.{a,so}`).

For microcontroller firmware, build with `--profile firmware` (smallest code, abort on panic). On a slow
CPU, `ts_set_ecdsa_verifier` can hand TLS certificate signature checks to a faster ECDSA library, such
as ESP-IDF's mbedTLS; it is used only after it passes a known-answer self-test.
