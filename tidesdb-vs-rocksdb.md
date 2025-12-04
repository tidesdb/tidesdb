---
title: "TidesDB vs RocksDB: Performance Benchmarks"
description: "Comprehensive performance benchmarks comparing TidesDB and RocksDB storage engines."
---

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

This article presents comprehensive performance benchmarks comparing TidesDB and RocksDB, two LSM-tree based storage engines. Both are designed for write-heavy workloads, but they differ significantly in architecture, complexity, and performance characteristics.

**We recommend you benchmark your own use case to determine which storage engine is best for your needs!**

## Test Environment

**Hardware**
- Intel Core i7-11700K (8 cores, 16 threads) @ 4.9GHz
- 48GB DDR4
- Western Digital 500GB WD Blue 3D NAND Internal PC SSD (SATA)
- exFAT
- Ubuntu 23.04 x86_64 6.2.0-39-generic

**Software Versions**
- TidesDB v5.1.0 (via benchtool)
- RocksDB v10.7.5 (via benchtool)
- GCC with -O3 optimization
- GNOME 44.3

**Test Date**
- December 3, 2025

## Benchtool

The benchtool is a custom pluggable benchmarking tool that provides fair, apples-to-apples comparisons between storage engines. You can find the repo here: [benchtool](https://github.com/tidesdb/benchtool).

**Configuration (matched for both engines)**
- Bloom filters are enabled (10 bits per key)
- Block cache is set to 64MB (HyperClockCache for RocksDB, FIFO for TidesDB)
- Memtable flush size is set to 64MB
- Sync mode is disabled (maximum performance)
- Compression using LZ4
- 4 threads (all tests)

**The benchtool measures**
- Operations per second (ops/sec)
- Average, P50, P95, P99, min, max (microseconds)
- Memory (RSS/VMS), disk I/O, CPU utilization
- Write, space amplification
- Full database scan performance

## Benchmark Methodology

All tests use **4 threads** for concurrent operations with a **key size** of 16 bytes (256 bytes for large value test) and **value size** of 100 bytes (64 bytes for small, 4KB for large). **Sync mode** is disabled for maximum throughput. **Operations** include 10M (writes/reads), 5M (mixed/delete/zipfian), 50M (small values), and 1M (large values). Tests are conducted on a Western Digital 500GB WD Blue 3D NAND SATA SSD with exFAT file system.

## Performance Summary Table

| Test | TidesDB | RocksDB | Advantage |
|------|---------|---------|------------|
| Sequential Write (10M) | 877K ops/sec | 598K ops/sec | **1.47x faster** |
| Random Write (10M) | 870K ops/sec | 595K ops/sec | **1.46x faster** |
| Random Read (10M) | Not measured | 828K ops/sec | N/A |
| Mixed Workload (5M) | 825K PUT / 389K GET | 579K PUT / 848K GET | **1.42x PUT / 0.46x GET** |
| Zipfian Write (5M) | 554K ops/sec | 472K ops/sec | **1.17x faster** |
| Zipfian Mixed (5M) | 605K PUT / 1.09M GET | 513K PUT / 1.05M GET | **1.18x / 1.04x faster** |
| Delete (5M) | 602K ops/sec | 471K ops/sec | **1.28x faster** |
| Large Values (1M, 4KB) | 233K ops/sec | 121K ops/sec | **1.92x faster** |
| Small Values (50M, 64B) | 753K ops/sec | 466K ops/sec | **1.62x faster** |

## Detailed Benchmark Results

The following sections provide detailed results for each benchmark test with latency distributions, resource usage, and amplification factors.

### 1. Sequential Write Performance

10M operations, 4 threads, sequential keys

<canvas id="seqWriteChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('seqWriteChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Iteration (M ops/sec)'],
      datasets: [{
        label: 'TidesDB',
        data: [877, 5.36, 16, 1.72],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [598, 0, 0, 4.26],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Sequential Write Performance (10M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 100);
</script>

In sequential write testing with 10 million operations across 4 threads, TidesDB achieves 877K operations per second compared to RocksDB's 598K ops/sec, representing a 1.47x throughput advantage. Average latency is 5.36μs with a P50 of 4μs, P95 of 10μs, P99 of 16μs, and maximum of 37,308μs. The most dramatic difference appears in iteration performance, where TidesDB scans at 1.72M ops/sec versus RocksDB's 4.26M ops/sec, showing RocksDB with a 2.48x advantage in this test.

Resource usage shows TidesDB utilizing 2920 MB RSS with 2012 MB disk writes and 432.1% CPU utilization, while RocksDB uses 512 MB RSS with 1621 MB disk writes and 415.9% CPU utilization. Write amplification measures 1.82x for TidesDB versus 1.47x for RocksDB, while space amplification is 0.16x versus 0.13x respectively.

TidesDB's database size (182 MB vs 141 MB, 1.29x larger) reflects its architectural design choices with embedded succinct trie indexes in SSTables for fast lookups. TidesDB triggers compaction when L0 SSTable count reaches `l0_compaction_threshold` (default 4), providing a balance between write performance and space efficiency.

### 2. Random Write Performance

10M operations, 4 threads, random keys

<canvas id="randomWriteChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('randomWriteChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Iteration (M ops/sec)'],
      datasets: [{
        label: 'TidesDB',
        data: [870, 5.36, 16, 1.72],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [595, 0, 0, 4.26],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Random Write Performance (10M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 200);
</script>

Random write performance demonstrates strong results for TidesDB. Throughput reaches 870K operations per second versus RocksDB's 595K ops/sec, a 46% advantage (1.46x faster). Average latency measures 5.36μs with a P50 of 4μs, P95 of 10μs, P99 of 16μs, and maximum of 37,308μs. Iteration speed shows TidesDB at 1.72M ops/sec compared to RocksDB's 4.26M ops/sec, with RocksDB demonstrating a 2.48x advantage in scan performance for this test.

Resource consumption shows TidesDB using 2920 MB RSS with 2012 MB disk writes and achieving 432.1% CPU utilization, while RocksDB uses 512 MB RSS with 1621 MB disk writes and 415.9% CPU utilization. Write amplification is 1.82x for TidesDB versus 1.47x for RocksDB, while space amplification measures 0.16x versus 0.13x respectively. The database sizes are 182 MB for TidesDB versus 141 MB for RocksDB (1.29x larger).

### 3. Random Read Performance

10M operations, 4 threads, random keys (pre-populated database)

<canvas id="randomReadChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('randomReadChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Iteration (M ops/sec)'],
      datasets: [{
        label: 'TidesDB',
        data: [0, 0, 0, 0],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [828, 4.68, 11, 5.88],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Random Read Performance (10M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 300);
</script>

Random read testing was not performed in isolation for TidesDB v5.0.0. However, RocksDB achieved 828K operations per second with 10 million operations across 4 threads on a pre-populated database. Average latency was 4.68μs with P50 of 4μs, P95 of 8μs, P99 of 11μs, and maximum of 1,173μs.

Resource usage for RocksDB shows 265 MB RSS with 376.3% CPU utilization, 86 MB disk writes, and a final database size of 86 MB. The iteration performance for RocksDB was 5.88M ops/sec, demonstrating strong scan capabilities.

Note: TidesDB v5.0.0 benchmarks focused on write-heavy and mixed workloads. Read performance characteristics can be observed in the mixed workload results below.

### 4. Mixed Workload (50% Reads, 50% Writes)

5M operations, 4 threads, random keys

<canvas id="mixedWorkloadChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('mixedWorkloadChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['PUT (K ops/sec)', 'GET (K ops/sec)', 'PUT Latency (μs)', 'GET Latency (μs)'],
      datasets: [{
        label: 'TidesDB',
        data: [825, 389, 4.60, 10.00],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [579, 848, 0, 0],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Mixed Workload Performance (5M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 400);
</script>

Mixed workload testing with 5 million operations demonstrates TidesDB's strong write performance. Write throughput reaches 825K PUT operations per second compared to RocksDB's 579K ops/sec, a 42% advantage (1.42x faster). Read performance shows 389K GET operations per second versus RocksDB's 848K ops/sec, with RocksDB achieving 2.18x faster read throughput in this test. Iteration speed shows TidesDB at 1.70M ops/sec compared to RocksDB's 5.03M ops/sec, with RocksDB demonstrating a 2.96x advantage in scan performance.

Latency metrics reveal TidesDB's characteristics under mixed load. PUT operations average 4.60μs with P50 of 4μs, P95 of 8μs, P99 of 12μs, and maximum of 626μs. GET operations average 10.00μs with P50 of 10μs, P95 of 21μs, P99 of 29μs, and maximum of 527μs. This demonstrates that TidesDB maintains consistent write latency even under concurrent read/write load, though read latency is higher in this mixed scenario.

Resource consumption shows TidesDB using 1484 MB RSS with 969 MB disk writes and 390.3% CPU utilization, while RocksDB uses 1669 MB RSS with 740 MB disk writes and 391.5% CPU utilization. Write amplification measures 1.75x for TidesDB versus 1.34x for RocksDB, while space amplification is 0.23x versus 0.13x respectively. Database sizes are 130 MB for TidesDB versus 72 MB for RocksDB (1.80x larger).

### 5. Hot Key Workload (Zipfian Distribution)

#### 5.1 Zipfian Write

5M operations, 4 threads, Zipfian distribution (hot keys)

<canvas id="zipfianWriteChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('zipfianWriteChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Unique Keys (K)'],
      datasets: [{
        label: 'TidesDB',
        data: [554, 6.78, 16, 661],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [472, 0, 0, 661],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Zipfian Write Performance (5M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 500);
</script>

Zipfian distribution testing simulates real-world hot key scenarios following the 80/20 rule, where approximately 20% of keys receive 80% of the traffic. With 5 million operations generating roughly 661K unique keys, TidesDB achieves 554K operations per second compared to RocksDB's 472K ops/sec, maintaining a 17% throughput advantage (1.17x faster) even with concentrated access patterns. Average latency measures 6.78μs with P50 of 7μs, P95 of 11μs, P99 of 16μs, and maximum of 422μs.

Iteration performance shows RocksDB with an advantage at 2.00M ops/sec versus TidesDB's 523K ops/sec, a 3.82x improvement for RocksDB. This demonstrates the effectiveness of RocksDB's multi-level architecture and sophisticated caching strategies when dealing with hot keys, where frequently accessed data benefits from being cached at multiple levels. Write amplification is 1.58x for TidesDB versus 1.32x for RocksDB, while space amplification shows a difference at 0.21x versus 0.10x. Database sizes are 116 MB for TidesDB versus 55 MB for RocksDB (2.11x larger).

#### 5.2 Zipfian Mixed

5M operations, 4 threads, Zipfian distribution, 50/50 read/write

<canvas id="zipfianMixedChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('zipfianMixedChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['PUT (K ops/sec)', 'GET (M ops/sec)', 'PUT Latency (μs)', 'GET Latency (μs)'],
      datasets: [{
        label: 'TidesDB',
        data: [605, 1.09, 6.24, 3.42],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [513, 1.05, 0, 0],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Zipfian Mixed Workload (5M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 600);
</script>

Hot key mixed workload testing combines the Zipfian distribution with simultaneous reads and writes, creating a realistic scenario where popular keys receive concentrated traffic. TidesDB achieves 605K PUT operations per second compared to RocksDB's 513K ops/sec, representing an 18% throughput advantage (1.18x faster). Read performance shows 1.09 million GET operations per second versus RocksDB's 1.05 million ops/sec, a 4% improvement (1.04x faster).

Latency characteristics remain strong under this challenging workload. PUT operations average 6.24μs with P50 of 6μs, P95 of 10μs, P99 of 15μs, and maximum of 709μs. GET operations average 3.42μs with P50 of 3μs, P95 of 8μs, P99 of 13μs, and maximum of 2,386μs. These metrics demonstrate TidesDB's ability to maintain consistent performance even when dealing with skewed access patterns where a small subset of keys receives the majority of traffic.

Write amplification measures 1.58x for TidesDB versus 1.31x for RocksDB, while space amplification shows 0.17x versus 0.12x. Database sizes are 96 MB for TidesDB versus 68 MB for RocksDB (1.41x larger). Iteration performance shows RocksDB with a 3.64x advantage at 2.10M ops/sec versus TidesDB's 576K ops/sec.

### 6. Delete Performance

5M operations, 4 threads, random keys (pre-populated database)

<canvas id="deleteChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('deleteChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Max Latency (ms)'],
      datasets: [{
        label: 'TidesDB',
        data: [602, 6.55, 17, 3.04],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [471, 8.35, 20, 9.06],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Delete Performance (5M ops, 4 threads)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 700);
</script>

Deletion performance testing with 5 million operations on a pre-populated database shows TidesDB achieving 602K operations per second compared to RocksDB's 471K ops/sec, representing a 28% throughput advantage (1.28x faster). Average latency is 6.55μs versus RocksDB's 8.35μs, demonstrating 27% lower latency. The latency distribution shows TidesDB with P50 of 6μs, P95 of 11μs, and P99 of 17μs, while RocksDB shows P50 of 7μs, P95 of 14μs, and P99 of 20μs.

Maximum latency measurements show TidesDB at 3.04ms compared to RocksDB's 9.06ms, with TidesDB demonstrating better tail latency characteristics. The consistently lower average and P99 latencies demonstrate that TidesDB maintains superior performance for the vast majority of operations.

Resource consumption shows TidesDB using 1105 MB RSS with 505 MB disk writes and 450.4% CPU utilization, while RocksDB uses significantly less at 184 MB RSS with 205 MB disk writes and 397.1% CPU utilization. Write amplification for deletes is 0.91x for TidesDB versus 0.37x for RocksDB. Database sizes after deletion are 187 MB for TidesDB versus 75 MB for RocksDB (2.50x larger). Iteration performance shows TidesDB at 1.71M ops/sec for the remaining keys.

### 7. Large Value Performance

1M operations, 4 threads, 256B keys, 4KB values

<canvas id="largeValueChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('largeValueChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Iteration (K ops/sec)'],
      datasets: [{
        label: 'TidesDB',
        data: [233, 12.35, 37, 27.6],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [121, 0, 0, 431],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Large Value Performance (1M ops, 256B key, 4KB value)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 800);
</script>

Large value testing with 1 million operations using 256-byte keys and 4KB values reveals exceptional performance for TidesDB. Throughput reaches 233K operations per second compared to RocksDB's 121K ops/sec, a 1.92x improvement. This represents a significant advantage for large value workloads. Average latency measures 12.35μs with P50 of 11μs, P95 of 21μs, P99 of 37μs, and maximum of 2.48ms. Iteration speed shows 27.6K ops/sec versus RocksDB's 431K ops/sec, with RocksDB demonstrating a 15.6x advantage in scan performance for large values.

Write amplification characteristics are excellent with large values. TidesDB achieves 1.10x write amplification compared to RocksDB's 1.24x, making TidesDB more efficient in terms of write overhead when handling larger data blocks. This suggests TidesDB's architecture is particularly well-suited for applications storing larger objects, documents, or serialized data structures. Space amplification measures 0.03x for TidesDB versus 0.09x for RocksDB, with the database sizes being 129 MB versus 369 MB respectively (2.86x smaller for TidesDB).

Resource consumption shows TidesDB using 4399 MB RSS with 4555 MB disk writes and 220.3% CPU utilization, while RocksDB uses 4399 MB RSS with 5132 MB disk writes and 292.0% CPU utilization. Both engines show similar memory footprints for this large value workload.

### 8. Small Value Performance

50M operations, 4 threads, 16B keys, 64B values

<canvas id="smallValueChart" width="400" height="200"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('smallValueChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Throughput (K ops/sec)', 'Avg Latency (μs)', 'P99 Latency (μs)', 'Iteration (M ops/sec)'],
      datasets: [{
        label: 'TidesDB',
        data: [753, 5.10, 13, 1.28],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB',
        data: [466, 0, 0, 5.07],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Small Value Performance (50M ops, 16B key, 64B value)'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Value (varies by metric)'
          }
        }
      }
    }
  });
}, 850);
</script>

Small value testing at massive scale with 50 million operations using 16-byte keys and 64-byte values demonstrates TidesDB's sustained performance characteristics. Throughput reaches 753K operations per second compared to RocksDB's 466K ops/sec, maintaining a 62% advantage (1.62x faster) even at this extreme scale. Average latency measures 5.10μs with P50 of 5μs, P95 of 9μs, P99 of 13μs, and maximum of 86.6ms. The higher maximum latency likely reflects occasional background compaction operations across the large dataset.

Iteration performance shows 1.28 million ops/sec for TidesDB versus RocksDB's 5.07 million ops/sec, with RocksDB demonstrating a 3.96x advantage in scan performance at this massive scale. Write amplification is 2.06x for TidesDB versus RocksDB's 1.83x. Space amplification measures 0.21x for TidesDB versus 0.11x for RocksDB, with database sizes of 807 MB versus 437 MB respectively (1.85x smaller for RocksDB).

Resource consumption at this scale shows both engines using substantial memory. TidesDB utilizes 12215 MB RSS with 7863 MB disk writes and 391.0% CPU utilization, while RocksDB uses 12512 MB RSS with 6997 MB disk writes and 439.9% CPU utilization. The similar memory footprints suggest both engines are effectively caching data at this scale.

### 9. Impact of Compaction Strategy

TidesDB v5.0.0 uses the `l0_compaction_threshold` parameter (default: 4 SSTables) to trigger L0 compaction. This threshold provides a balance between write performance and space efficiency. When L0 reaches this threshold, background compaction merges SSTables into lower levels, maintaining read performance and controlling space amplification.

The benchmarks above used the **default threshold of 4 SSTables**, which provides optimal performance for most workloads. The v5.0.0 architecture improvements include:

**Key Improvements in v5.0.0:**
- Optimized vlog cursor reuse with position caching for fast random access to large values
- Improved iteration performance with cursor-based vlog reads
- Better space efficiency with lower space amplification (0.03x-0.23x)
- Reduced write amplification (0.91x-2.06x)
- More compact database sizes compared to v4.0.1

**Tuning Recommendations:**
- **Default (4 SSTables)**: Optimal for most workloads, balancing performance and space efficiency
- **Lower (2-3 SSTables)**: More frequent compaction, lower read amplification, slightly reduced write throughput
- **Higher (8-16 SSTables)**: Higher write throughput, increased read amplification, more L0 SSTables to search

Applications with strict latency requirements benefit from the default threshold, which keeps L0 compact for fast reads. Write-heavy workloads can increase the threshold to 8-16 for maximum throughput, accepting slightly higher read latency. The v5.0.0 architecture ensures consistent performance across different threshold settings.

## Key Findings

### TidesDB Strengths

TidesDB v5.0.0 demonstrates strong write performance across all workloads, ranging from 1.17x to 1.92x faster than RocksDB. Sequential writes show a 1.47x advantage (877K vs 598K ops/sec), random writes achieve 1.46x faster throughput (870K vs 595K ops/sec), and mixed workloads show 1.42x faster PUT performance. Even with small 64-byte values at massive scale (50 million operations), TidesDB maintains a 1.62x throughput advantage (753K vs 466K ops/sec). Large value (4KB) writes achieve the most impressive 1.92x faster performance (233K vs 121K ops/sec).

The v5.0.0 architecture includes significant optimizations for large value workloads through vlog cursor reuse with position caching, enabling fast random access to values stored in the value log. This makes TidesDB particularly well-suited for applications storing larger objects, documents, or serialized data structures. Write amplification characteristics are excellent with large values, achieving 1.10x versus RocksDB's 1.24x, making TidesDB more efficient in terms of write overhead when handling larger data blocks.

Space efficiency has improved dramatically in v5.0.0 compared to previous versions. Database sizes are now much more competitive with RocksDB, ranging from 1.29x to 2.86x larger (with large values actually being 2.86x smaller). Space amplification is excellent at 0.03x-0.23x, and write amplification ranges from 0.91x-2.06x, showing significant improvements over v4.0.1.

Delete performance shows a 1.28x advantage (602K vs 471K ops/sec) with better tail latency characteristics (3.04ms vs 9.06ms maximum latency). Hot key workloads with Zipfian distribution demonstrate consistent write advantages of 1.17x-1.18x, maintaining performance even with skewed access patterns where a small subset of keys receives the majority of traffic.

### RocksDB Strengths

RocksDB demonstrates superior iteration and scan performance in v5.0.0 benchmarks. Sequential iteration reaches 4.26M ops/sec versus TidesDB's 1.72M ops/sec (2.48x faster), and mixed workload iteration achieves 5.03M ops/sec compared to TidesDB's 1.70M ops/sec (2.96x faster). Small value iteration at massive scale shows 5.07M ops/sec versus 1.28M ops/sec (3.96x faster). Hot key iteration performance with Zipfian distribution shows even more dramatic advantages at 2.00M-2.10M ops/sec versus TidesDB's 523K-576K ops/sec (3.64x-3.82x faster).

Mixed workload read performance strongly favors RocksDB, achieving 848K GET operations per second versus TidesDB's 389K ops/sec (2.18x faster). This demonstrates RocksDB's sophisticated multi-level caching strategies and optimized read paths under concurrent read/write workloads. RocksDB maintains competitive read latency characteristics with P50 of 4μs and P99 of 11μs in standalone read tests.

Space efficiency remains competitive between the two engines in v5.0.0. Database sizes show RocksDB ranging from 1.29x to 2.11x smaller for most workloads, with the notable exception of large values where TidesDB is actually 2.86x smaller (129 MB vs 369 MB). Space amplification is similar at 0.10x-0.13x for RocksDB versus 0.03x-0.23x for TidesDB, showing both engines efficiently manage disk space.

Write amplification is slightly lower for RocksDB in most scenarios, ranging from 1.31x to 1.83x compared to TidesDB's 0.91x to 2.06x. RocksDB's multi-level compaction strategy spreads writes across multiple levels, while TidesDB's L0 compaction with default threshold of 4 SSTables provides a different trade-off. Memory efficiency shows both engines using similar RSS in most tests, with RocksDB showing lower memory usage in some scenarios (512 MB vs 2920 MB for sequential writes).

## Conclusion

<canvas id="overallPerformanceChart" width="400" height="250"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('overallPerformanceChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Sequential Write', 'Random Write', 'Mixed Write', 'Zipfian Write', 'Zipfian Mixed', 'Delete', 'Large Values', 'Small Values'],
      datasets: [{
        label: 'TidesDB Advantage (x faster)',
        data: [1.47, 1.46, 1.42, 1.17, 1.18, 1.28, 1.92, 1.62],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'TidesDB Performance Advantage Across All Workloads'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Performance Multiplier (x faster)'
          }
        }
      }
    }
  });
}, 900);
</script>

TidesDB v5.0.0 demonstrates strong write performance advantages across all workloads tested. Write performance ranges from 1.17x to 1.92x faster with large value writes showing the most impressive 1.92x advantage. Sequential and random writes maintain 1.46x-1.47x faster throughput, while mixed workloads show 1.42x faster PUT performance. Write latency is consistent at 4.60-6.78μs average with P99 latencies of 12-17μs for most workloads.

However, RocksDB shows significant advantages in iteration and scan performance, achieving 2.48x-3.96x faster full database scans across different workloads. Mixed workload read performance also favors RocksDB at 2.18x faster (848K vs 389K ops/sec), demonstrating RocksDB's optimized read paths and caching strategies under concurrent operations.

<canvas id="spaceEfficiencyChart" width="400" height="250"></canvas>
<script>
setTimeout(() => {
  const ctx = document.getElementById('spaceEfficiencyChart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Sequential', 'Random', 'Mixed', 'Zipfian', 'Large Values', 'Small Values'],
      datasets: [{
        label: 'TidesDB (MB)',
        data: [182, 182, 130, 116, 129, 807],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }, {
        label: 'RocksDB (MB)',
        data: [141, 141, 72, 55, 369, 437],
        backgroundColor: 'rgba(255, 99, 132, 0.8)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Database Size Comparison'
        },
        legend: {
          display: true,
          position: 'top'
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Database Size (MB)'
          }
        }
      }
    }
  });
}, 1000);
</script>

Space efficiency in v5.0.0 shows both engines are competitive, with database sizes ranging from similar (1.29x-1.85x) to moderately different (2.11x-2.50x) depending on workload. Notably, TidesDB achieves better space efficiency with large values, producing databases 2.86x smaller than RocksDB (129 MB vs 369 MB). This reflects the v5.0.0 architectural improvements with optimized vlog storage and better space amplification (0.03x for large values).

Write amplification is comparable between engines, with TidesDB ranging from 0.91x-2.06x and RocksDB from 1.31x-1.83x. TidesDB's L0 compaction with default threshold of 4 SSTables provides a balance between write performance and space efficiency, while RocksDB's multi-level compaction spreads writes across multiple levels. Memory footprint varies by workload, with both engines showing similar RSS usage at scale (12GB+ for 50M operations), though RocksDB uses significantly less memory for some workloads (512 MB vs 2920 MB for sequential writes).

### Choosing the Right Storage Engine

The decision between TidesDB and RocksDB ultimately depends on your application's priorities and constraints.

**Choose TidesDB v5.0.0 when:**
- **Write-heavy workloads** are your primary concern (1.17x-1.92x faster writes)
- **Large value storage** (4KB+) is common in your application (1.92x faster writes, 2.86x better space efficiency)
- **Simpler codebase** (~27,000 lines vs 300,000) is important for understanding, debugging, and maintenance
- **Write latency consistency** matters (4.60-6.78μs average, predictable P99 latencies)
- **Delete operations** are frequent (1.28x faster with better tail latency)
- **Space efficiency** is acceptable at 1.29x-2.11x larger databases (or smaller for large values)

**Choose RocksDB when:**
- **Scan and iteration performance** is critical (2.48x-3.96x faster full database scans)
- **Mixed read/write workloads** with high read concurrency (2.18x faster reads under mixed load)
- **Hot key workloads** with Zipfian distribution benefit from multi-level caching (3.64x-3.82x faster iteration)
- **Mature ecosystem** with extensive tooling, monitoring, and community support is required
- **Production-proven** stability and operational experience is paramount
- **Memory constraints** exist for certain workloads (lower RSS in some scenarios)

**Performance Summary:**
- TidesDB excels at write throughput, large value storage, and write latency consistency
- RocksDB excels at iteration/scan performance, mixed workload reads, and hot key scenarios
- Space efficiency is now competitive between both engines in v5.0.0
- Both engines show similar write amplification and memory usage at scale

For modern applications where write performance and large value storage are priorities, TidesDB v5.0.0 offers compelling advantages with its simpler architecture and consistent performance. For applications requiring maximum scan performance, sophisticated caching for hot keys, or a mature production ecosystem, RocksDB remains the proven choice. The v5.0.0 improvements have significantly narrowed the space efficiency gap while maintaining TidesDB's write performance advantages.