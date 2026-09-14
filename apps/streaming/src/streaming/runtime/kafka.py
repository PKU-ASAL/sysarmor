from pyflink.common import Types
from pyflink.common.serialization import DeserializationSchema, SerializationSchema
from pyflink.java_gateway import get_gateway
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.checkpoint_storage import FileSystemCheckpointStorage
from pyflink.datastream.connectors.kafka import (
    DeliveryGuarantee,
    KafkaOffsetResetStrategy,
    KafkaOffsetsInitializer,
    KafkaRecordSerializationSchema,
    KafkaSink,
    KafkaSource,
)

from streaming.runtime.config import StreamingConfig


class ByteArraySchema(SerializationSchema, DeserializationSchema):
    """Use Flink core's byte-preserving schema for protobuf Kafka values."""

    def __init__(self):
        schema = get_gateway().jvm.io.sysarmor.streaming.ByteArraySchema()
        SerializationSchema.__init__(self, schema)
        DeserializationSchema.__init__(self, schema)


def configure_environment(config: StreamingConfig):
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(config.parallelism)
    env.enable_checkpointing(config.checkpoint_interval_ms)
    storage = FileSystemCheckpointStorage(config.checkpoint_uri_for_job)
    env.get_checkpoint_config().set_checkpoint_storage(storage)
    if config.kafka_connector_jar:
        env.add_jars(config.kafka_connector_jar)
    return env


def source(env, topic: str, group_id: str, config: StreamingConfig):
    kafka_source = (
        KafkaSource.builder()
        .set_bootstrap_servers(config.brokers)
        .set_topics(topic)
        .set_group_id(group_id)
        .set_starting_offsets(
            KafkaOffsetsInitializer.committed_offsets(KafkaOffsetResetStrategy.EARLIEST)
        )
        .set_value_only_deserializer(ByteArraySchema())
        .build()
    )
    return env.from_source(
        kafka_source,
        _no_watermark(),
        f"kafka-{topic}",
        Types.PRIMITIVE_ARRAY(Types.BYTE()),
    )


def sink(stream, topic: str, config: StreamingConfig, transaction_prefix: str):
    serializer = (
        KafkaRecordSerializationSchema.builder()
        .set_topic(topic)
        .set_value_serialization_schema(ByteArraySchema())
        .build()
    )
    kafka_sink = (
        KafkaSink.builder()
        .set_bootstrap_servers(config.brokers)
        .set_record_serializer(serializer)
        .set_delivery_guarantee(DeliveryGuarantee.EXACTLY_ONCE)
        .set_transactional_id_prefix(transaction_prefix)
        .set_property("transaction.timeout.ms", "900000")
        .build()
    )
    stream.sink_to(kafka_sink).uid(f"sink-{topic}").name(f"kafka-{topic}")


def _no_watermark():
    from pyflink.common.watermark_strategy import WatermarkStrategy

    return WatermarkStrategy.no_watermarks()
