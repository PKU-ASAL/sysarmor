#!/usr/bin/env bash
set -euo pipefail

broker="${SYSARMOR_KAFKA_BROKERS:-kafka:9092}"
manifest="${SYSARMOR_KAFKA_TOPIC_MANIFEST:-/opt/sysarmor/kafka/topics.tsv}"
topics=/opt/kafka/bin/kafka-topics.sh
configs=/opt/kafka/bin/kafka-configs.sh

while IFS=$'\t' read -r name partitions replication cleanup retention; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  "$topics" --bootstrap-server "$broker" --create --if-not-exists \
    --topic "$name" --partitions "$partitions" --replication-factor "$replication"
  "$configs" --bootstrap-server "$broker" --alter --entity-type topics --entity-name "$name" \
    --add-config "cleanup.policy=$cleanup,retention.ms=$retention"
  description="$("$topics" --bootstrap-server "$broker" --describe --topic "$name")"
  [[ "$description" == *"PartitionCount: $partitions"* ]] || {
    echo "topic $name has unexpected partition contract: $description" >&2
    exit 1
  }
done <"$manifest"

echo "sysarmor Kafka topics are ready"
