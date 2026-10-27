"""
SafeSOC — Simulator Log Formats
Pure builders: (org, host/user objects, timestamp in UTC, **fields) ->
one source-native payload dict. No randomness unless the caller passes
an rng; the same inputs always give the same payload.
"""
