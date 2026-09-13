"""LexTier OSS core — Python parity package (protocol lextier/1)."""

from .errors import LexError, err
from .canonical import canonicalize, canonical_bytes, is_safe_int
from .strictjson import parse_json_strict, parse_json_bytes
from .yamlparse import parse_yaml, compile_yaml
from .hashing import sha256_hex, hash_json, hash_domain, hash_domain_json, DOMAIN, RE, ZERO_HASH
from .ids import is_id, require_id, csprng_id_gen, fixture_id_gen, PREFIX, ALPHABET
from .registry import (TOOL_SPECS, TOOL_NAMES, BUILTIN_DENIED, REGISTRY_HASH,
                       validate_call, validate_call_shape, validate_call_args,
                       is_registered_tool, valid_path, sort_by_bytes, TIER_RANK)
from .policy import compile_policy, evaluate, policy_hash, EVAL_REASONS
from .stats import compute_reviewer_stats
from .audit import (EVENT_TYPES, TERMINAL_STATES, LEGAL, event_hash, sign_message,
                    sign_entry, sign_head, sign_rotation, verify_entry_sig,
                    verify_head_sig, verify_rotation_sig, verify_chain,
                    public_key_from_seed, ed_sign, ed_verify, content_hash)
from .sdk import LexTierClient, LexTierError

__version__ = "0.1.0"
