# Architecture Overview
See docs/01_architecture.md in the repository for the full architecture document.
The 12-stage pipeline processes every packet: capture → context build → filters →
flow engine → TCP reassembly → 14 analyzers → attribution → events → output.
