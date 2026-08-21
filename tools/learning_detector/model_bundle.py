"""FeatureSchemaV2 validation and cross-language canonical digests."""

from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Any

SCHEMA = "FeatureSchemaV2"
PREPROCESSOR = "process-profile-v1"


def float32(value: float) -> float:
    return struct.unpack("!f", struct.pack("!f", value))[0]


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def refresh_digests(bundle: dict[str, Any]) -> dict[str, Any]:
    bundle["model_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, False)).hexdigest()
    bundle["payload_digest"] = "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest()
    return bundle


def digest_material(bundle: dict[str, Any], include_model_digest: bool) -> bytes:
    purpose = "sysarmor.learning-model/payload-digest/v2" if include_model_digest else "sysarmor.learning-model/model-digest/v2"
    result = length_prefixed(purpose)
    for value in (bundle["model_ref"], bundle["model_version"], bundle["feature_schema"], bundle["preprocessor_version"]):
        result += length_prefixed(value)
    if include_model_digest:
        result += length_prefixed(bundle["model_digest"])
    embedding = bundle["embedding"]
    result += uint32(embedding["dimension"]) + uint32(embedding["min_n"]) + uint32(embedding["max_n"]) + uint32(embedding["bucket_count"])
    result += uint32(len(embedding["tokens"]))
    for token in embedding["tokens"]:
        result += length_prefixed(token["token"]) + float_slice(token["vector"])
    result += uint32(len(embedding["subwords"]))
    for subword in embedding["subwords"]:
        result += uint32(subword["bucket"]) + float_slice(subword["vector"])
    rarity = bundle["rarity"]
    result += number(rarity["default_file"]) + number(rarity["default_network"])
    result += weighted_values(rarity["files"]) + weighted_values(rarity["networks"])
    vae = bundle["vae"]
    result += uint32(vae["input_dimension"]) + uint32(vae["hidden_dimension"]) + uint32(vae["latent_dimension"])
    for name in ("encoder_weights", "encoder_bias", "mean_weights", "mean_bias", "logvar_weights",
                 "logvar_bias", "decoder_weights", "decoder_bias", "output_weights", "output_bias"):
        result += float_slice(vae[name])
    result += number(bundle["stability"]["default"]) + weighted_values(bundle["stability"]["processes"])
    return result + number(bundle["threshold"])


def validate_bundle(bundle: dict[str, Any]) -> None:
    required = {"model_ref", "model_version", "model_digest", "feature_schema", "preprocessor_version",
                "embedding", "rarity", "vae", "stability", "threshold", "payload_digest"}
    if not required.issubset(bundle):
        raise ValueError("model bundle fields are required")
    if bundle["feature_schema"] != SCHEMA or bundle["preprocessor_version"] != PREPROCESSOR:
        raise ValueError("unsupported model bundle schema")
    embedding, vae = bundle["embedding"], bundle["vae"]
    dimension = embedding["dimension"]
    if dimension <= 0 or vae["input_dimension"] != dimension:
        raise ValueError("model dimensions are invalid")
    numeric = [bundle["threshold"], bundle["rarity"]["default_file"], bundle["rarity"]["default_network"], bundle["stability"]["default"]]
    for group in (embedding["tokens"], embedding["subwords"]):
        for item in group:
            if len(item["vector"]) != dimension:
                raise ValueError("embedding vector dimension mismatch")
            numeric.extend(item["vector"])
    if not all(isinstance(value, (int, float)) and math.isfinite(value) for value in numeric):
        raise ValueError("model parameters must be finite")
    if bundle["model_digest"] != "sha256:" + hashlib.sha256(digest_material(bundle, False)).hexdigest():
        raise ValueError("model digest mismatch")
    if bundle["payload_digest"] != "sha256:" + hashlib.sha256(digest_material(bundle, True)).hexdigest():
        raise ValueError("model payload digest mismatch")


def uint32(value: int) -> bytes:
    return struct.pack("!I", value)


def number(value: float) -> bytes:
    return struct.pack("!f", float32(value))


def length_prefixed(value: str) -> bytes:
    encoded = value.encode()
    return uint32(len(encoded)) + encoded


def float_slice(values: list[float]) -> bytes:
    return uint32(len(values)) + b"".join(number(value) for value in values)


def weighted_values(values: list[dict[str, Any]]) -> bytes:
    return uint32(len(values)) + b"".join(length_prefixed(item["value"]) + number(item["weight"]) for item in values)
