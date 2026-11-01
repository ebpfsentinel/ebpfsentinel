#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

use domain::inventory::{
    DatabaseOutcome, DatabaseReading, MappedObject, Package, PackageManager, PackageState,
    ProcessObjects, RootInventory, RootScope, loaded_objects,
};

/// A host with `packages` packages of eight files each, and `processes`
/// processes mapping the same forty libraries plus one executable of their
/// own: the shape of a busy node, where most mappings are shared.
fn node(packages: usize, processes: usize) -> (Vec<RootInventory>, Vec<ProcessObjects>) {
    let packages: Vec<Package> = (0..packages)
        .map(|p| Package {
            manager: PackageManager::Dpkg,
            name: format!("package-{p}"),
            version: "1.0-1".into(),
            arch: Some("amd64".into()),
            state: PackageState::Installed,
            files: Some(
                (0..8)
                    .map(|f| format!("/lib/x86_64-linux-gnu/lib{p}-{f}.so.1"))
                    .collect(),
            ),
        })
        .collect();
    let roots = vec![RootInventory {
        scope: RootScope::Host,
        pid: 1,
        databases: vec![DatabaseReading {
            manager: PackageManager::Dpkg,
            path: "/var/lib/dpkg/status".into(),
            outcome: DatabaseOutcome::Read { packages },
        }],
        error: None,
    }];
    let shared: Vec<Arc<MappedObject>> = (0..40)
        .map(|i| {
            Arc::new(MappedObject {
                dev: 2049,
                ino: i,
                path: format!("/usr/lib/x86_64-linux-gnu/lib{i}-0.so.1"),
                deleted: false,
            })
        })
        .collect();
    let processes = (0..processes)
        .map(|pid| {
            let mut objects = shared.clone();
            objects.push(Arc::new(MappedObject {
                dev: 2049,
                ino: 1_000_000 + pid as u64,
                path: format!("/usr/bin/daemon-{pid}"),
                deleted: false,
            }));
            ProcessObjects {
                pid: pid as u32 + 2,
                root_pid: Some(1),
                objects,
            }
        })
        .collect();
    (roots, processes)
}

fn bench_join(c: &mut Criterion) {
    let mut group = c.benchmark_group("loaded_objects");
    for processes in [100usize, 1_000, 5_000] {
        let (roots, procs) = node(2_000, processes);
        let loaded = loaded_objects(&roots, &procs);
        assert_eq!(loaded.objects.len(), 40 + processes);
        assert_eq!(
            loaded.objects.iter().filter(|o| o.owner.is_some()).count(),
            40
        );
        group.bench_with_input(
            BenchmarkId::from_parameter(processes),
            &(roots, procs),
            |b, (roots, procs)| b.iter(|| loaded_objects(black_box(roots), black_box(procs))),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_join);
criterion_main!(benches);
