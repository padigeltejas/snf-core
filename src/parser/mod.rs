// src/parser/mod.rs
//
// Parser module — top-level re-export for TLS record parsing.
//
// ── What lives here ───────────────────────────────────────────────────────────
//
//   This module contains the raw TLS record parser: a low-level byte-level
//   parser that extracts ClientHello and ServerHello fields directly from
//   TLS record bytes BEFORE TCP reassembly provides a complete stream.
//
//   It is distinct from intelligence/tls_intelligence.rs which performs
//   SCORING on an already-populated PacketContext. The parser layer provides
//   the raw field extraction that feeds into the higher-level intelligence.
//
// ── Module ───────────────────────────────────────────────────────────────────
//
//   tls_intelligence — raw TLS record parser (ClientHello/ServerHello field
//                      extraction from raw TLS bytes). Called by analyzers/tls.rs
//                      for early TLS version detection before full handshake.
//
// ── Note on naming ───────────────────────────────────────────────────────────
//
//   Both src/parser/tls_intelligence.rs and src/intelligence/tls_intelligence.rs
//   contain a TlsIntelligence struct. They serve different purposes:
//
//   src/parser/tls_intelligence.rs  — byte-level TLS record parser.
//                                     Extracts raw fields from wire bytes.
//                                     Used for early/partial TLS analysis.
//
//   src/intelligence/tls_intelligence.rs — high-level TLS intelligence scorer.
//                                          Reads from populated PacketContext.
//                                          Applies risk scoring after analyzers run.
//
//   These are complementary, not duplicates. The parser layer feeds the
//   intelligence layer via PacketContext fields set during analysis.

pub mod tls_intelligence;
