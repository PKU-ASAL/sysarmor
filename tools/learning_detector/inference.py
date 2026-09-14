"""Deterministic FeatureSchemaV2 inference matching the Go Agent."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from model_bundle import float32


def natural_tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[\W_]+", value.lower(), flags=re.UNICODE) if token]


def profile_vector(profile: dict[str, Any], bundle: dict[str, Any]) -> list[float]:
    rarity = bundle["rarity"]
    resources: list[tuple[list[str], float]] = []
    for path in profile.get("files", []):
        resources.append((natural_tokens(path), lookup_weight(path, rarity["files"], rarity["default_file"])))
    for address in profile.get("networks", []):
        resources.append((natural_tokens(address), lookup_weight(address, rarity["networks"], rarity["default_network"])))
    command_weight = float32(float32(rarity["default_file"] + rarity["default_network"]) / 2)
    if resources:
        command_weight = float32(float32_sum(weight for _, weight in resources) / len(resources))
    command = " ".join([profile.get("binary", ""), *profile.get("argv", [])])
    features = [(natural_tokens(command), command_weight), *resources]
    result = [0.0] * bundle["embedding"]["dimension"]
    for tokens, weight in features:
        vector = sentence_vector(tokens, bundle["embedding"])
        result = [float32(current + float32(value * weight)) for current, value in zip(result, vector)]
    return result


def sentence_vector(tokens: list[str], embedding: dict[str, Any]) -> list[float]:
    vectors = [token_vector(token, embedding) for token in tokens]
    vectors = [vector for vector in vectors if vector is not None]
    if not vectors:
        return [0.0] * embedding["dimension"]
    return [float32(float32_sum(vector[index] for vector in vectors) / len(vectors))
            for index in range(embedding["dimension"])]


def token_vector(token: str, embedding: dict[str, Any]) -> list[float] | None:
    known = {item["token"]: item["vector"] for item in embedding["tokens"]}
    subwords = {item["bucket"]: item["vector"] for item in embedding["subwords"]}
    vectors: list[list[float]] = []
    if token in known:
        vectors.append(known[token])
    wrapped = f"<{token}>"
    for size in range(embedding["min_n"], embedding["max_n"] + 1):
        for start in range(len(wrapped) - size + 1):
            bucket = fnv1a(wrapped[start:start + size]) % embedding["bucket_count"]
            if bucket in subwords:
                vectors.append(subwords[bucket])
    if not vectors:
        return None
    return [float32(float32_sum(vector[index] for vector in vectors) / len(vectors))
            for index in range(embedding["dimension"])]


def score_profile(profile: dict[str, Any], bundle: dict[str, Any]) -> float:
    vector = profile_vector(profile, bundle)
    reconstructed = reconstruct(vector, bundle["vae"])
    squares = (float32(float32(value - output) ** 2) for value, output in zip(vector, reconstructed))
    error = float32(float32_sum(squares) / len(vector))
    name = Path(profile.get("binary", "")).name.lower()
    stability = lookup_weight(name, bundle["stability"]["processes"], bundle["stability"]["default"])
    return float32(math.log(max(float32(error / stability), 1e-12)))


def reconstruct(vector: list[float], vae: dict[str, Any]) -> list[float]:
    hidden = dense(vector, vae["encoder_weights"], vae["encoder_bias"], vae["hidden_dimension"], True)
    mean = dense(hidden, vae["mean_weights"], vae["mean_bias"], vae["latent_dimension"], False)
    decoded = dense(mean, vae["decoder_weights"], vae["decoder_bias"], vae["hidden_dimension"], True)
    return dense(decoded, vae["output_weights"], vae["output_bias"], vae["input_dimension"], False)


def dense(values: list[float], weights: list[float], bias: list[float], outputs: int, relu: bool) -> list[float]:
    result = []
    for row in range(outputs):
        value = float32(bias[row])
        for column, current in enumerate(values):
            value = float32(value + float32(weights[row * len(values) + column] * current))
        result.append(max(value, 0.0) if relu else value)
    return result


def lookup_weight(value: str, values: list[dict[str, Any]], fallback: float) -> float:
    return next((item["weight"] for item in values if item["value"] == value), fallback)


def float32_sum(values: Any) -> float:
    result = 0.0
    for value in values:
        result = float32(result + value)
    return result


def fnv1a(value: str) -> int:
    result = 2166136261
    for byte in value.encode():
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result
