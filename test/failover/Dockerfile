# Image for the failover harness node (test infrastructure only -- not shipped with the library).
# One container = one cluster node (primary or replica) pointed at a shared S3/MinIO bucket.
# Build context is the repo root:  docker build -f test/failover/Dockerfile -t tidesdb-node:ci .

FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake build-essential ca-certificates \
        liblz4-dev libzstd-dev libsnappy-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTIDESDB_WITH_SANITIZER=OFF \
        -DTIDESDB_WITH_S3=ON \
    && cmake --build build --target tidesdb tidesdb_node -j"$(nproc)"

FROM ubuntu:24.04
# the scenario driver speaks the node's TCP protocol via kubectl exec.
# iptables-- the partition scenario severs this pod's egress to MinIO from inside its own netns
# (needs the NET_ADMIN capability, set on the pod), so no CNI NetworkPolicy support is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash iptables libcurl4 liblz4-1 libzstd1 libsnappy1v5 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/tidesdb_node /usr/local/bin/tidesdb_node
COPY --from=build /src/build/libtidesdb.so* /usr/local/lib/
RUN ldconfig
# data dir for the local working set; the bucket is remote (MinIO)
RUN mkdir -p /data
ENV TDB_NODE_DATA_DIR=/data
ENTRYPOINT ["/usr/local/bin/tidesdb_node"]
