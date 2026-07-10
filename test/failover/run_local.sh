#!/usr/bin/env bash
#
# local cross-process failover smoke test for the object-store single-writer fence.
# starts real tidesdb_node processes against a shared filesystem bucket (the fs backend uses
# flock, so the fence works across processes on one host) and drives two scenarios:
#
#   failover_catchup    the replica is given a huge sync interval so it never polls; all of the
#                       outgoing primary's data must arrive via the promotion catch-up. proves the
#                       catch-up gates on the outgoing epoch (the ordering fix) rather than
#                       skipping it as stale. writes enough through a small write buffer to build
#                       many sstables and WAL generations.
#   zombie_fence        after a replica is promoted, the old primary keeps writing. its next
#                       publish must fail the lease renew and self-demote, and its post-promotion
#                       writes must never appear on the new primary.
#
# this is the same node binary the kind + minio harness runs in pods; here it is a fast,
# dependency-free smoke. requires bash with /dev/tcp.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE="${TDB_NODE_BIN:-$ROOT/build-rel/tidesdb_node}"
LIBDIR="${TDB_NODE_LIBDIR:-$ROOT/build-rel}"
SCRATCH="${TDB_FAILOVER_SCRATCH:-$ROOT/test/failover/.scratch}"
WRITE_BUFFER="${TDB_NODE_WRITE_BUFFER:-65536}"
VOLUME="${TDB_FAILOVER_VOLUME:-600}"
FLUSH_EVERY=150
PORT_P=7401
PORT_R=7402

fail=0
pids=()

cleanup() {
    for p in "${pids[@]:-}"; do kill -9 "$p" 2>/dev/null; done
    wait 2>/dev/null
}

# always remove everything the run created. set TDB_FAILOVER_KEEP=1 to keep the scratch
# dir (data, buckets, logs) for debugging.
on_exit() {
    cleanup
    [ -n "${TDB_FAILOVER_KEEP:-}" ] || rm -rf "$SCRATCH"
}
trap on_exit EXIT

cmd() { # cmd port "LINE" -> single reply line
    local port=$1 line=$2 resp=""
    exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null || { echo "DOWN"; return 1; }
    printf '%s\n' "$line" >&3
    IFS= read -r resp <&3
    exec 3>&- 3<&-
    printf '%s' "${resp%$'\r'}"
}

bulk_put() { # bulk_put port start end prefix -- pipelined over one connection
    local port=$1 start=$2 end=$3 pre=$4 i
    exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    for ((i = start; i <= end; i++)); do printf 'PUT %s%d v%d\n' "$pre" "$i" "$i" >&3; done
    for ((i = start; i <= end; i++)); do IFS= read -r _ <&3; done
    exec 3>&- 3<&-
}

verify_range() { # verify_range port start end prefix -> count of correct values
    local port=$1 start=$2 end=$3 pre=$4 i n=0 resp
    exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null || { echo 0; return; }
    for ((i = start; i <= end; i++)); do printf 'GET %s%d\n' "$pre" "$i" >&3; done
    for ((i = start; i <= end; i++)); do
        IFS= read -r resp <&3
        [ "${resp%$'\r'}" = "VAL v$i" ] && n=$((n + 1))
    done
    exec 3>&- 3<&-
    echo "$n"
}

# write [start,end] in batches, flushing every FLUSH_EVERY keys to roll memtables into sstables
load_volume() {
    local port=$1 start=$2 end=$3 pre=$4 b
    for ((b = start; b <= end; b += FLUSH_EVERY)); do
        local e=$((b + FLUSH_EVERY - 1)); [ "$e" -gt "$end" ] && e=$end
        bulk_put "$port" "$b" "$e" "$pre"
        cmd "$port" FLUSH >/dev/null
    done
}

stat_field() { cmd "$1" STAT | grep -o "$2=[0-9]*" | cut -d= -f2; }

wait_ready() {
    local port=$1 i
    for i in $(seq 1 50); do
        [ "$(cmd "$port" PING 2>/dev/null)" = "PONG" ] && return 0
        sleep 0.2
    done
    return 1
}

wait_val() {
    local port=$1 key=$2 want=$3 i
    for i in $(seq 1 100); do
        [ "$(cmd "$port" "GET $key")" = "VAL $want" ] && return 0
        sleep 0.2
    done
    return 1
}

# block until the node's async upload pipeline has drained -- every rotated WAL generation, sstable
# and manifest is in the bucket. under wal_sync=0 the uploads are asynchronous, so killing the
# primary before this drains leaves the newest WAL generation only on local disk (lost on crash),
# and the failover catch-up can then only reach what actually made it to the bucket.
#
# upload_queue alone is not enough, a job the worker has dequeued is off the queue but still
# in-flight (not yet in the bucket), so the queue reads 0 while an upload is mid-transfer. we gate
# on completions instead -- the queue must be empty AND total_uploads (a completion counter) must
# stop advancing for several consecutive polls, i.e. no queued and no in-flight work remains.
wait_uploads_drained() { # wait_uploads_drained port
    local port=$1 i last=-1 stable=0 q t
    for i in $(seq 1 300); do # up to ~30s
        q=$(stat_field "$port" upload_queue)
        t=$(stat_field "$port" total_uploads)
        if [ "$q" = "0" ] && [ "$t" = "$last" ]; then
            stable=$((stable + 1))
            [ "$stable" -ge 3 ] && return 0
        else
            stable=0
        fi
        last="$t"
        sleep 0.1
    done
    return 1
}

start_node() { # start_node port replica data_dir bucket sync_us id [wal_sync_on_commit]
    # wal_sync defaults off, the failover/zombie scenarios get durability from flushed sstables +
    # the fenced manifest, so they avoid a synchronous WAL upload per put. the rpo_zero scenario
    # passes 1 to require that acked-but-unflushed writes reach the bucket and survive a crash.
    local wal_sync="${7:-0}"
    LD_LIBRARY_PATH="$LIBDIR" TDB_NODE_PORT="$1" TDB_NODE_REPLICA="$2" TDB_NODE_DATA_DIR="$3" \
        TDB_NODE_BUCKET="$4" TDB_NODE_REPLICA_SYNC_US="$5" TDB_NODE_ID="$6" \
        TDB_NODE_WAL_SYNC_ON_COMMIT="$wal_sync" TDB_NODE_WRITE_BUFFER="$WRITE_BUFFER" \
        "$NODE" >"$SCRATCH/$6.log" 2>&1 &
    pids+=("$!")
}

check() { # check label actual expected
    if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: got [$2] want [$3]"; fail=1; fi
}
check_ge() { # check_ge label actual min
    if [ "$2" -ge "$3" ] 2>/dev/null; then echo "  ok   $1 ($2)"; else echo "  FAIL $1: got [$2] want >= [$3]"; fail=1; fi
}

scenario_failover_catchup() {
    echo "== scenario failover_catchup (volume=$VOLUME) =="
    local bucket="$SCRATCH/fc_bucket" dp="$SCRATCH/fc_p" dr="$SCRATCH/fc_r"
    rm -rf "$bucket" "$dp" "$dr"; mkdir -p "$bucket" "$dp" "$dr"
    pids=()

    start_node "$PORT_P" 0 "$dp" "$bucket" 500000 fc_primary
    # replica with a 1h sync interval, it must rely on the promotion catch-up, not polling
    start_node "$PORT_R" 1 "$dr" "$bucket" 3600000000 fc_replica
    wait_ready "$PORT_P" || { echo "  FAIL primary not ready"; fail=1; return; }
    wait_ready "$PORT_R" || { echo "  FAIL replica not ready"; fail=1; return; }

    load_volume "$PORT_P" 1 "$VOLUME" k

    check_ge "primary built many sstables" "$(stat_field "$PORT_P" sstables)" 2
    check_ge "primary rolled many wal generations" "$(stat_field "$PORT_P" walgen)" 3
    check_ge "primary holds a lease" "$(stat_field "$PORT_P" primary_epoch)" 1

    # the replica never polled (huge interval), so it should have none of the data
    check "replica behind before failover" "$(verify_range "$PORT_R" 1 "$VOLUME" k)" 0

    # simulate a graceful-enough failover -- let the primary finish uploading so the bucket holds
    # every committed write before it "crashes". without this the newest WAL generation is still
    # in flight and the catch-up correctly recovers only what reached the bucket (a wal_sync=0
    # RPO>0 crash), which is a harness race, not an engine fault
    wait_uploads_drained "$PORT_P" || { echo "  FAIL primary uploads did not drain in time"; fail=1; }

    kill -9 "${pids[0]}" 2>/dev/null
    check "promote replica" "$(cmd "$PORT_R" PROMOTE)" "OK 2"

    # every write must have arrived via the promotion catch-up (the ordering fix)
    check "all keys present after catch-up" "$(verify_range "$PORT_R" 1 "$VOLUME" k)" "$VOLUME"
    check "new primary mode" "$(stat_field "$PORT_R" replica_mode)" 0
    cleanup; pids=()
}

scenario_zombie_fence() {
    echo "== scenario zombie_fence (volume=$VOLUME) =="
    local bucket="$SCRATCH/zf_bucket" dp="$SCRATCH/zf_p" dr="$SCRATCH/zf_r"
    rm -rf "$bucket" "$dp" "$dr"; mkdir -p "$bucket" "$dp" "$dr"
    pids=()

    start_node "$PORT_P" 0 "$dp" "$bucket" 300000 zf_primary
    start_node "$PORT_R" 1 "$dr" "$bucket" 300000 zf_replica
    wait_ready "$PORT_P" || { echo "  FAIL primary not ready"; fail=1; return; }
    wait_ready "$PORT_R" || { echo "  FAIL replica not ready"; fail=1; return; }

    load_volume "$PORT_P" 1 "$VOLUME" a
    check_ge "primary built many sstables" "$(stat_field "$PORT_P" sstables)" 2
    wait_val "$PORT_R" "a$VOLUME" "v$VOLUME" || { echo "  FAIL replica did not converge"; fail=1; cleanup; return; }

    # promote the replica while the old primary stays alive (the zombie)
    check "promote replica" "$(cmd "$PORT_R" PROMOTE)" "OK 2"

    # the zombie keeps writing, then publishes -- the publish must fence it and self-demote
    bulk_put "$PORT_P" 1 200 z
    cmd "$PORT_P" FLUSH >/dev/null
    sleep 0.5
    check "zombie self-demoted" "$(stat_field "$PORT_P" replica_mode)" 1

    # the new primary takes writes; zombie writes must never appear on it
    load_volume "$PORT_R" 1 200 b

    check "pre-failover data preserved" "$(verify_range "$PORT_R" 1 "$VOLUME" a)" "$VOLUME"
    check "new primary writes visible" "$(verify_range "$PORT_R" 1 200 b)" 200
    check "zombie writes fenced out" "$(verify_range "$PORT_R" 1 200 z)" 0
    cleanup; pids=()
}

scenario_rpo_zero() {
    echo "== scenario rpo_zero =="
    local bucket="$SCRATCH/rz_bucket" dp="$SCRATCH/rz_p" dr="$SCRATCH/rz_r"
    rm -rf "$bucket" "$dp" "$dr"; mkdir -p "$bucket" "$dp" "$dr"
    pids=()

    # a write buffer just large enough to hold the unflushed batch without auto-rotating it (the
    # small volume-scenario buffer would flush it and defeat the premise), but not so large that
    # wal_sync_on_commit's per-commit re-upload of the active WAL copies megabytes each time
    local WRITE_BUFFER=262144

    # both nodes run wal_sync_on_commit=1, so every committed write is uploaded to the bucket.
    # the replica gets a 1h sync interval, so the unflushed writes can only reach it via the
    # promotion catch-up's WAL replay -- proving they were durable, not merely still local.
    start_node "$PORT_P" 0 "$dp" "$bucket" 500000 rz_primary 1
    start_node "$PORT_R" 1 "$dr" "$bucket" 3600000000 rz_replica 1
    wait_ready "$PORT_P" || { echo "  FAIL primary not ready"; fail=1; return; }
    wait_ready "$PORT_R" || { echo "  FAIL replica not ready"; fail=1; return; }

    # flushed baseline so the CF, config and a manifest exist in the bucket
    bulk_put "$PORT_P" 1 20 base
    check "baseline flush" "$(cmd "$PORT_P" FLUSH)" "OK"

    # acked writes that are committed but never flushed -- they live only in the WAL, which
    # wal_sync_on_commit uploads to the bucket per commit. a modest count keeps the run quick:
    # each RPO=0 commit synchronously ships the WAL, which is inherently a few-per-second operation
    bulk_put "$PORT_P" 1 40 rpo

    # hard-kill the primary with no chance to flush, simulating a crash
    kill -9 "${pids[0]}" 2>/dev/null
    check "promote replica" "$(cmd "$PORT_R" PROMOTE)" "OK 2"

    # RPO=0 the unflushed-but-acked writes must survive via WAL replay in the catch-up
    check "unflushed acked writes survived (rpo=0)" "$(verify_range "$PORT_R" 1 40 rpo)" 40
    check "baseline preserved" "$(verify_range "$PORT_R" 1 20 base)" 20
    cleanup; pids=()
}

mkdir -p "$SCRATCH"
[ -x "$NODE" ] || { echo "node binary not found at $NODE (build it first)"; exit 2; }

scenario_failover_catchup
scenario_zombie_fence
scenario_rpo_zero

echo
if [ "$fail" -eq 0 ]; then echo "ALL FAILOVER SCENARIOS PASSED"; else echo "FAILOVER SCENARIOS FAILED"; fi
exit "$fail"
