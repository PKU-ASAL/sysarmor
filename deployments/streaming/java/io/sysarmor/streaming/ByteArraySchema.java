package io.sysarmor.streaming;

import org.apache.flink.api.common.serialization.DeserializationSchema;
import org.apache.flink.api.common.serialization.SerializationSchema;
import org.apache.flink.api.common.typeinfo.PrimitiveArrayTypeInfo;
import org.apache.flink.api.common.typeinfo.TypeInformation;

public final class ByteArraySchema
        implements SerializationSchema<byte[]>, DeserializationSchema<byte[]> {
    @Override
    public byte[] serialize(byte[] element) {
        return element;
    }

    @Override
    public byte[] deserialize(byte[] message) {
        return message;
    }

    @Override
    public boolean isEndOfStream(byte[] message) {
        return false;
    }

    @Override
    public TypeInformation<byte[]> getProducedType() {
        return PrimitiveArrayTypeInfo.BYTE_PRIMITIVE_ARRAY_TYPE_INFO;
    }
}
