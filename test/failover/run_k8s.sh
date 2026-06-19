#!/usr/bin/env bash
#
# cloud-simulation failover test: real pods on a kind cluster, fencing against a real MinIO
# bucket over the S3 connector's conditional writes (not the fs/flock shortcut). a "node loss" is
# a real pod deletion and the writers are separate containers. one primary + three replicas let
# the matrix cover fan-out replication, a failover the surviving replicas re-follow, split-brain
# fencing of a live zombie, and cascading (sequential) failovers with a monotonic epoch.
#
# assumes a working kubectl context (the kind cluster) with the node image loaded as
# tidesdb-node:ci. test infrastructure only.
set -u

K8S_DIR="$(cd "$(dirname "$0")/k8s" && pwd)"
BUCKET=tidesdb-failover
REPLICAS=(tdb-replica-0 tdb-replica-1 tdb-replica-2)
ALL_PODS=(tdb-primary "${REPLICAS[@]}")
fail=0

check() { if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: got [$2] want [$3]"; fail=1; fi; }

# run a one-line node command inside a pod via bash /dev/tcp to the node's localhost port
kexec() {
    kubectl exec "$1" -- bash -c '
        exec 3<>/dev/tcp/127.0.0.1/7400 || exit 1
        printf "%s\n" "$1" >&3
        IFS= read -r resp <&3
        printf "%s" "$resp"
    ' _ "$2" 2>/dev/null | tr -d '\r'
}

# pipeline a range of PUTs over one connection inside the pod (one exec, not one per key)
kbulk_put() { # pod start end prefix
    kubectl exec "$1" -- bash -c '
        exec 3<>/dev/tcp/127.0.0.1/7400 || exit 1
        for ((i='"$2"'; i<='"$3"'; i++)); do printf "PUT '"$4"'%d v%d\n" "$i" "$i" >&3; done
        for ((i='"$2"'; i<='"$3"'; i++)); do IFS= read -r _ <&3; done
    ' >/dev/null 2>&1
}

# count how many keys in a range read back correctly (one exec)
kverify() { # pod start end prefix -> count
    kubectl exec "$1" -- bash -c '
        exec 3<>/dev/tcp/127.0.0.1/7400 || exit 1
        n=0
        for ((i='"$2"'; i<='"$3"'; i++)); do printf "GET '"$4"'%d\n" "$i" >&3; done
        for ((i='"$2"'; i<='"$3"'; i++)); do
            IFS= read -r r <&3; r="${r%$'\''\r'\''}"
            [ "$r" = "VAL v$i" ] && n=$((n+1))
        done
        echo "$n"
    ' 2>/dev/null | tr -d '\r'
}

kstat_field() { kexec "$1" STAT | grep -o "$2=[0-9]*" | cut -d= -f2; }

# run mc inside the cluster (the runner cannot reach the MinIO ClusterIP directly)
mc_do() {
    local name="mc-$RANDOM"
    kubectl run "$name" --image=minio/mc:latest --restart=Never --rm -i --quiet --command -- \
        sh -c "mc alias set m http://minio:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}

# wait until reading <key> on <pod> returns <want> (bounded)
kwait_val() { # pod key want
    local i
    for i in $(seq 1 60); do
        [ "$(kexec "$1" "GET $2")" = "VAL $3" ] && return 0
        sleep 1
    done
    return 1
}

# wait until every listed pod has the full [1..count] range of <prefix>
wait_all_converge() { # count prefix pod...
    local count=$1 prefix=$2; shift 2
    local p i
    for p in "$@"; do
        for i in $(seq 1 60); do
            [ "$(kverify "$p" 1 "$count" "$prefix")" = "$count" ] && break
            sleep 1
        done
    done
}

# fresh nodes + empty bucket for a scenario
reset_cluster() {
    kubectl delete pod "${ALL_PODS[@]}" --ignore-not-found --wait=true >/dev/null 2>&1
    mc_do "mc rb --force m/$BUCKET >/dev/null 2>&1; mc mb -p m/$BUCKET >/dev/null"
    kubectl apply -f "$K8S_DIR/nodes.yaml" >/dev/null
    local p
    for p in "${ALL_PODS[@]}"; do kubectl wait --for=condition=Ready "pod/$p" --timeout=180s >/dev/null; done
}

# ----------------------------------------------------------------------------
# every replica receives what the primary writes
scenario_fanout_converge() {
    echo "== k8s scenario fanout_converge =="
    reset_cluster

    kbulk_put tdb-primary 1 50 k
    check "primary flush" "$(kexec tdb-primary FLUSH)" "OK"
    wait_all_converge 50 k "${REPLICAS[@]}"

    local r
    for r in "${REPLICAS[@]}"; do check "$r converged" "$(kverify "$r" 1 50 k)" 50; done
}

# kill the primary, promote one replica, and the surviving replicas must re-follow the new primary
scenario_failover_refollow() {
    echo "== k8s scenario failover_refollow =="
    reset_cluster

    kbulk_put tdb-primary 1 50 k
    kexec tdb-primary FLUSH >/dev/null
    wait_all_converge 50 k "${REPLICAS[@]}"

    kubectl delete pod tdb-primary --wait=true >/dev/null 2>&1
    check "promote replica-0" "$(kexec tdb-replica-0 PROMOTE)" "OK 2"
    check "promoted holds all data" "$(kverify tdb-replica-0 1 50 k)" 50
    check "promoted is primary" "$(kstat_field tdb-replica-0 replica_mode)" 0

    # the new primary takes fresh writes; the still-replicas must pick them up
    kbulk_put tdb-replica-0 1 30 m
    kexec tdb-replica-0 FLUSH >/dev/null
    wait_all_converge 30 m tdb-replica-1 tdb-replica-2
    check "replica-1 follows new primary" "$(kverify tdb-replica-1 1 30 m)" 30
    check "replica-2 follows new primary" "$(kverify tdb-replica-2 1 30 m)" 30
}

# a promoted replica fences the still-alive old primary
scenario_zombie_fence() {
    echo "== k8s scenario zombie_fence =="
    reset_cluster

    kbulk_put tdb-primary 1 50 a
    kexec tdb-primary FLUSH >/dev/null
    wait_all_converge 50 a "${REPLICAS[@]}"

    check "promote replica-0" "$(kexec tdb-replica-0 PROMOTE)" "OK 2"

    # the zombie keeps writing then publishes -- the fence must demote it
    kbulk_put tdb-primary 1 20 z
    kexec tdb-primary FLUSH >/dev/null
    sleep 2
    check "zombie self-demoted" "$(kstat_field tdb-primary replica_mode)" 1
    check "zombie writes fenced out" "$(kverify tdb-replica-0 1 20 z)" 0
    check "pre-failover data preserved" "$(kverify tdb-replica-0 1 50 a)" 50
}

# two sequential failovers; the epoch advances monotonically and data survives both
scenario_cascading_failover() {
    echo "== k8s scenario cascading_failover =="
    reset_cluster

    kbulk_put tdb-primary 1 40 c
    kexec tdb-primary FLUSH >/dev/null
    wait_all_converge 40 c "${REPLICAS[@]}"

    # first failover: primary -> replica-0 (epoch 2)
    kubectl delete pod tdb-primary --wait=true >/dev/null 2>&1
    check "first promote (epoch 2)" "$(kexec tdb-replica-0 PROMOTE)" "OK 2"
    kbulk_put tdb-replica-0 1 20 d
    kexec tdb-replica-0 FLUSH >/dev/null
    wait_all_converge 20 d tdb-replica-1

    # second failover: replica-0 -> replica-1 (epoch 3)
    kubectl delete pod tdb-replica-0 --wait=true >/dev/null 2>&1
    check "second promote (epoch 3)" "$(kexec tdb-replica-1 PROMOTE)" "OK 3"
    check "data from before both failovers" "$(kverify tdb-replica-1 1 40 c)" 40
    check "data from the first new primary" "$(kverify tdb-replica-1 1 20 d)" 20
}

# ----------------------------------------------------------------------------
echo "Applying MinIO..."
kubectl apply -f "$K8S_DIR/minio.yaml" >/dev/null
kubectl rollout status deploy/minio --timeout=180s >/dev/null

scenario_fanout_converge
scenario_failover_refollow
scenario_zombie_fence
scenario_cascading_failover

echo
if [ "$fail" -eq 0 ]; then echo "ALL K8S FAILOVER SCENARIOS PASSED"; else echo "K8S FAILOVER SCENARIOS FAILED"; fi
exit "$fail"
