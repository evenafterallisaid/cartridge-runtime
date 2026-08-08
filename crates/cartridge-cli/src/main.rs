use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cartridge_core::{CartridgeArchive, PackOptions, ResolutionPlan, pack, resolve_dependencies};
use cartridge_runtime::{ExecutionTrace, Runtime};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "cartridge",
    version,
    about = "pack and run portable wasm cartridges"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// build a cartridge archive from a manifest and component
    Pack {
        manifest: PathBuf,
        #[arg(long)]
        component: PathBuf,
        #[arg(long)]
        assets: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// show a cartridge's metadata without running it
    Inspect {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// validate a cartridge without executing it
    Verify { package: PathBuf },
    /// show requested and provided cartridge services
    Deps {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// resolve a cartridge against candidate dependency packages
    Resolve {
        root: PathBuf,
        candidates: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// execute a cartridge
    Run {
        package: PathBuf,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// replay a cartridge from a recorded trace
    Replay {
        package: PathBuf,
        trace: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Pack {
            manifest,
            component,
            assets,
            output,
        } => pack_command(&manifest, &component, assets.as_deref(), &output),
        Command::Inspect { package, json } => inspect_command(&package, json),
        Command::Verify { package } => verify_command(&package),
        Command::Deps { package, json } => deps_command(&package, json),
        Command::Resolve {
            root,
            candidates,
            json,
        } => resolve_command(&root, &candidates, json),
        Command::Run {
            package,
            trace,
            args,
        } => run_command(&package, trace.as_deref(), &args),
        Command::Replay {
            package,
            trace,
            args,
        } => replay_command(&package, &trace, &args),
    }
}

fn pack_command(
    manifest: &Path,
    component: &Path,
    assets: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let packed = pack(&PackOptions {
        manifest: manifest.to_owned(),
        component: component.to_owned(),
        assets: assets.map(Path::to_owned),
        output: output.to_owned(),
    })?;
    println!(
        "packed {} {} -> {}",
        packed.cartridge.name,
        packed.cartridge.version,
        output.display()
    );
    Ok(())
}

fn inspect_command(package: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&archive.manifest)?);
    } else {
        print_manifest(&archive);
    }
    Ok(())
}

fn verify_command(package: &Path) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not verify {}", package.display()))?;
    println!(
        "verified {} {}: component and {} asset(s)",
        archive.manifest.cartridge.id,
        archive.manifest.cartridge.version,
        archive.assets.len()
    );
    Ok(())
}

fn deps_command(package: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dependencies": archive.manifest.dependencies,
                "services": archive.manifest.services,
            }))?
        );
    } else {
        print_relationships(&archive);
    }
    Ok(())
}

fn resolve_command(root: &Path, candidates: &[PathBuf], json: bool) -> Result<()> {
    let root = CartridgeArchive::open(root)
        .with_context(|| format!("could not inspect {}", root.display()))?;
    let mut manifests = Vec::with_capacity(candidates.len());
    for path in candidates {
        let candidate = CartridgeArchive::open(path)
            .with_context(|| format!("could not inspect {}", path.display()))?;
        manifests.push(candidate.manifest);
    }
    let plan = resolve_dependencies(&root.manifest, &manifests)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_resolution(&plan);
    }
    Ok(())
}

fn run_command(package: &Path, trace: Option<&Path>, args: &[String]) -> Result<()> {
    let report = Runtime::new()?.run_file(package, args)?;
    println!("{}", report.output);
    eprintln!("fuel consumed: {}", report.fuel_consumed);
    if let Some(path) = trace {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(&report.trace)?)?;
        eprintln!("trace: {}", path.display());
    }
    Ok(())
}

fn replay_command(package: &Path, trace: &Path, args: &[String]) -> Result<()> {
    let bytes =
        fs::read(trace).with_context(|| format!("could not read trace {}", trace.display()))?;
    let trace: ExecutionTrace = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid trace {}", trace.display()))?;
    let event_count = trace.events.len();
    let report = Runtime::new()?.replay_file(package, args, trace)?;
    println!("{}", report.output);
    eprintln!(
        "replay matched {event_count} event(s), {} fuel",
        report.fuel_consumed
    );
    Ok(())
}

fn print_manifest(archive: &CartridgeArchive) {
    let manifest = &archive.manifest;
    println!("{} {}", manifest.cartridge.name, manifest.cartridge.version);
    println!("id: {}", manifest.cartridge.id);
    if !manifest.cartridge.description.is_empty() {
        println!("description: {}", manifest.cartridge.description);
    }
    println!("assets: {}", archive.assets.len());
    println!(
        "permissions: clock={}, random={}, assets={}",
        manifest.permissions.clock, manifest.permissions.random, manifest.permissions.assets
    );
    println!("fuel: {}", manifest.runtime.fuel);
    println!("memory: {} bytes", manifest.runtime.memory_bytes);
    println!("component sha256: {}", manifest.integrity.component_sha256);
    println!("dependencies: {}", manifest.dependencies.len());
    println!("provided services: {}", manifest.services.provides.len());
}

fn print_relationships(archive: &CartridgeArchive) {
    let manifest = &archive.manifest;
    if manifest.dependencies.is_empty() {
        println!("requires: none");
    } else {
        println!("requires:");
        for dependency in &manifest.dependencies {
            let requirement = if dependency.optional {
                "optional"
            } else {
                "required"
            };
            println!(
                "  {} -> {} {} ({requirement})",
                dependency.alias, dependency.cartridge, dependency.version
            );
            for interface in &dependency.interfaces {
                println!("    {interface}");
            }
            if !dependency.reason.is_empty() {
                println!("    reason: {}", dependency.reason);
            }
        }
    }

    if manifest.services.provides.is_empty() {
        println!("provides: none");
    } else {
        println!("provides:");
        for service in &manifest.services.provides {
            println!(
                "  {} -> {} ({})",
                service.name, service.interface, service.visibility
            );
            if !service.description.is_empty() {
                println!("    {}", service.description);
            }
        }
    }
}

fn print_resolution(plan: &ResolutionPlan) {
    if plan.resolved.is_empty() {
        println!("resolved: none");
    } else {
        println!("resolved:");
        for dependency in &plan.resolved {
            println!(
                "  {} -> {} {}",
                dependency.alias, dependency.cartridge, dependency.version
            );
            for interface in &dependency.interfaces {
                println!("    {interface}");
            }
        }
    }
    if !plan.unavailable_optional.is_empty() {
        println!("unavailable optional:");
        for dependency in &plan.unavailable_optional {
            println!(
                "  {} -> {}: {}",
                dependency.alias, dependency.cartridge, dependency.reason
            );
        }
    }
}
