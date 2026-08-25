FROM flink:1.20.2-scala_2.12-java17

USER root
COPY deployments/streaming/java /tmp/sysarmor-streaming-java
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip curl openjdk-17-jdk-headless \
    && mkdir -p /tmp/sysarmor-streaming-classes \
    && /usr/lib/jvm/java-17-openjdk-amd64/bin/javac -cp '/opt/flink/lib/*' \
      -d /tmp/sysarmor-streaming-classes \
      /tmp/sysarmor-streaming-java/io/sysarmor/streaming/ByteArraySchema.java \
    && /usr/lib/jvm/java-17-openjdk-amd64/bin/jar \
      -cf /opt/flink/lib/sysarmor-streaming-runtime.jar \
      -C /tmp/sysarmor-streaming-classes . \
    && apt-get purge -y openjdk-17-jdk-headless openjdk-17-jre-headless \
    && apt-get autoremove -y \
    && ln -s /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir apache-flink==1.20.2 \
    && curl -fsSL -o /opt/flink/lib/flink-sql-connector-kafka-3.3.0-1.20.jar \
      https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/3.3.0-1.20/flink-sql-connector-kafka-3.3.0-1.20.jar \
    && curl -fsSL -o /opt/flink/lib/flink-s3-fs-presto-1.20.2.jar \
      https://repo1.maven.org/maven2/org/apache/flink/flink-s3-fs-presto/1.20.2/flink-s3-fs-presto-1.20.2.jar

COPY streaming /opt/sysarmor/streaming
ENV PYTHONPATH=/opt/sysarmor/streaming/src
WORKDIR /opt/sysarmor/streaming
USER flink
