"""Offline FastText, VAE, DBSCAN, and threshold training."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from gensim.models import FastText
from sklearn.cluster import DBSCAN

from inference import natural_tokens, profile_vector, score_profile
from model_bundle import PREPROCESSOR, SCHEMA, float32, refresh_digests


@dataclass(frozen=True)
class TrainingConfig:
    dimension: int = 16
    hidden_dimension: int = 12
    latent_dimension: int = 8
    bucket_count: int = 2048
    epochs: int = 80
    seed: int = 7
    target_rate: float = 0.005
    dbscan_eps: float = 0.5
    dbscan_min_samples: int = 2


class VAE(torch.nn.Module):
    def __init__(self, inputs: int, hidden: int, latent: int):
        super().__init__()
        self.encoder = torch.nn.Linear(inputs, hidden)
        self.mean = torch.nn.Linear(hidden, latent)
        self.logvar = torch.nn.Linear(hidden, latent)
        self.decoder = torch.nn.Linear(latent, hidden)
        self.output = torch.nn.Linear(hidden, inputs)

    def forward(self, values: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        hidden = torch.relu(self.encoder(values))
        mean, logvar = self.mean(hidden), self.logvar(hidden)
        latent = mean + torch.randn_like(mean) * torch.exp(0.5 * logvar)
        return self.output(torch.relu(self.decoder(latent))), mean, logvar


def train_bundle(training: list[dict[str, Any]], calibration: list[dict[str, Any]], config: TrainingConfig) -> dict[str, Any]:
    if not training or not calibration:
        raise ValueError("training and calibration profiles are required")
    embedding = train_fasttext(training, config)
    rarity_maps = idf_weights(training)
    bundle = base_bundle(embedding, rarity_maps, config)
    training_vectors = [profile_vector(profile, bundle) for profile in training]
    bundle["vae"] = train_vae(training_vectors, config)
    names = [Path(profile.get("binary", "")).name.lower() for profile in training]
    stability = stability_scores(names, training_vectors, config.dbscan_eps, config.dbscan_min_samples)
    bundle["stability"]["processes"] = [{"value": name, "weight": value} for name, value in sorted(stability.items())]
    scores = [score_profile(profile, bundle) for profile in calibration]
    bundle["threshold"] = calibrated_threshold(scores, config.target_rate)
    return refresh_digests(bundle)


def train_fasttext(profiles: list[dict[str, Any]], config: TrainingConfig) -> dict[str, Any]:
    sentences = training_sentences(profiles)
    model = FastText(vector_size=config.dimension, window=5, min_count=1, workers=1, sg=1,
                     seed=config.seed, min_n=3, max_n=4, bucket=config.bucket_count)
    model.build_vocab(corpus_iterable=sentences)
    model.train(corpus_iterable=sentences, total_examples=len(sentences), epochs=max(config.epochs, 1))
    tokens = []
    for token in sorted(model.wv.key_to_index):
        index = model.wv.key_to_index[token]
        tokens.append({"token": token, "vector": quantize(model.wv.vectors_vocab[index])})
    subwords = [{"bucket": index, "vector": quantize(vector)} for index, vector in enumerate(model.wv.vectors_ngrams)]
    return {"dimension": config.dimension, "min_n": 3, "max_n": 4, "bucket_count": config.bucket_count,
            "tokens": tokens, "subwords": subwords}


def training_sentences(profiles: list[dict[str, Any]]) -> list[list[str]]:
    result: list[list[str]] = []
    for profile in profiles:
        command = " ".join([profile.get("binary", ""), *profile.get("argv", [])])
        for value in [command, *profile.get("files", []), *profile.get("networks", [])]:
            tokens = natural_tokens(value)
            if tokens:
                result.append(tokens)
    if not result:
        raise ValueError("training profiles contain no textual features")
    return result


def idf_weights(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(profiles)
    file_counts = Counter(value for profile in profiles for value in set(profile.get("files", [])))
    network_counts = Counter(value for profile in profiles for value in set(profile.get("networks", [])))
    return {
        "default_file": float32(max(math.log(max(total, 2)), 1.0)),
        "default_network": float32(max(math.log(max(total, 2)), 1.0)),
        "files": {value: float32(math.log(total / count)) for value, count in sorted(file_counts.items())},
        "networks": {value: float32(math.log(total / count)) for value, count in sorted(network_counts.items())},
    }


def train_vae(vectors: list[list[float]], config: TrainingConfig) -> dict[str, Any]:
    torch.manual_seed(config.seed)
    torch.use_deterministic_algorithms(True)
    model = VAE(config.dimension, config.hidden_dimension, config.latent_dimension).cpu()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    values = torch.tensor(vectors, dtype=torch.float32)
    for _ in range(config.epochs):
        optimizer.zero_grad()
        output, mean, logvar = model(values)
        reconstruction = torch.nn.functional.mse_loss(output, values)
        divergence = -0.5 * torch.mean(1 + logvar - mean.square() - logvar.exp())
        (reconstruction + 0.001 * divergence).backward()
        optimizer.step()
    return export_vae(model, config)


def export_vae(model: VAE, config: TrainingConfig) -> dict[str, Any]:
    return {
        "input_dimension": config.dimension, "hidden_dimension": config.hidden_dimension,
        "latent_dimension": config.latent_dimension,
        "encoder_weights": quantize(model.encoder.weight), "encoder_bias": quantize(model.encoder.bias),
        "mean_weights": quantize(model.mean.weight), "mean_bias": quantize(model.mean.bias),
        "logvar_weights": quantize(model.logvar.weight), "logvar_bias": quantize(model.logvar.bias),
        "decoder_weights": quantize(model.decoder.weight), "decoder_bias": quantize(model.decoder.bias),
        "output_weights": quantize(model.output.weight), "output_bias": quantize(model.output.bias),
    }


def stability_scores(names: list[str], vectors: list[list[float]], eps: float, min_samples: int) -> dict[str, float]:
    grouped: dict[str, list[list[float]]] = defaultdict(list)
    for name, vector in zip(names, vectors):
        grouped[name].append(vector)
    result = {}
    for name, values in grouped.items():
        labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(np.asarray(values, dtype=np.float32))
        result[name] = float(max(1, len({int(label) for label in labels if label >= 0})))
    return result


def calibrated_threshold(scores: list[float], target_rate: float) -> float:
    if not scores or not 0 < target_rate < 1:
        raise ValueError("valid calibration scores and target rate are required")
    allowed = math.floor(len(scores) * target_rate)
    boundary = sorted((float32(score) for score in scores), reverse=True)[allowed]
    return float(np.nextafter(np.float32(boundary), np.float32(math.inf), dtype=np.float32))


def base_bundle(embedding: dict[str, Any], rarity: dict[str, Any], config: TrainingConfig) -> dict[str, Any]:
    return {
        "model_ref": "model:process-profile-v2", "model_version": "2", "model_digest": "",
        "feature_schema": SCHEMA, "preprocessor_version": PREPROCESSOR, "embedding": embedding,
        "rarity": {
            "default_file": rarity["default_file"], "default_network": rarity["default_network"],
            "files": [{"value": value, "weight": weight} for value, weight in rarity["files"].items()],
            "networks": [{"value": value, "weight": weight} for value, weight in rarity["networks"].items()],
        },
        "vae": empty_vae(config), "stability": {"default": 1.0, "processes": []},
        "threshold": 0.0, "payload_digest": "",
    }


def empty_vae(config: TrainingConfig) -> dict[str, Any]:
    zeros = lambda count: [0.0] * count
    return {
        "input_dimension": config.dimension, "hidden_dimension": config.hidden_dimension, "latent_dimension": config.latent_dimension,
        "encoder_weights": zeros(config.hidden_dimension * config.dimension), "encoder_bias": zeros(config.hidden_dimension),
        "mean_weights": zeros(config.latent_dimension * config.hidden_dimension), "mean_bias": zeros(config.latent_dimension),
        "logvar_weights": zeros(config.latent_dimension * config.hidden_dimension), "logvar_bias": zeros(config.latent_dimension),
        "decoder_weights": zeros(config.hidden_dimension * config.latent_dimension), "decoder_bias": zeros(config.hidden_dimension),
        "output_weights": zeros(config.dimension * config.hidden_dimension), "output_bias": zeros(config.dimension),
    }


def quantize(values: Any) -> list[float]:
    array = values.detach().cpu().numpy() if isinstance(values, torch.Tensor) else np.asarray(values)
    return [float32(float(value)) for value in array.reshape(-1)]
