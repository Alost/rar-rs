//! rar — create and modify RAR5 archives.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "a" | "create" => cmd_create(&args[2..]),
        "l" | "list" => cmd_list(&args[2..]),
        "i" | "info" => cmd_info(&args[2..]),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        _ => {
            eprintln!("unknown command: {}", args[1]);
            usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("rar: {e}");
        process::exit(1);
    }
}

fn usage() {
    eprintln!("rar-rs — create RAR5 archives");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  rar a <archive.rar> <files...>   Create archive from files");
    eprintln!("  rar l <archive.rar>              List archive contents");
    eprintln!("  rar i <archive.rar>              Show archive info");
}

fn cmd_create(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: rar a <archive.rar> <files...>".into());
    }
    let archive_path = &args[0];
    let files = &args[1..];

    let mut rar =
        rar5::RarArchive::create(archive_path).map_err(|e| format!("create: {e}"))?;

    for file in files {
        rar.add(file, 3).map_err(|e| format!("add {file}: {e}"))?;
    }

    rar.close().map_err(|e| format!("close: {e}"))?;
    println!("Created {archive_path} ({} file(s))", files.len());
    Ok(())
}

fn cmd_list(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: rar l <archive.rar>".into());
    }
    let rar = rar5::RarArchive::open(&args[0]).map_err(|e| format!("{e}"))?;

    println!(
        "{:>10}  {:>10}  {:>6}  {:<8}  Name",
        "Size", "Packed", "Ratio", "Method"
    );
    println!("{}", "-".repeat(60));

    let mut total_size = 0u64;
    let mut total_packed = 0u64;

    for entry in rar.list() {
        let ratio = if entry.is_dir() {
            "  dir".to_string()
        } else if entry.size() > 0 {
            format!("{:.1}%", entry.compressed_size() as f64 / entry.size() as f64 * 100.0)
        } else {
            " 0.0%".to_string()
        };

        println!(
            "{:>10}  {:>10}  {:>6}  {:<8}  {}",
            entry.size(),
            entry.compressed_size(),
            ratio,
            entry.method_name(),
            entry.name()
        );

        total_size += entry.size();
        total_packed += entry.compressed_size();
    }

    println!("{}", "-".repeat(60));
    let overall = if total_size > 0 {
        format!("{:.1}%", total_packed as f64 / total_size as f64 * 100.0)
    } else {
        " 0.0%".to_string()
    };
    println!(
        "{total_size:>10}  {total_packed:>10}  {overall:>6}  {:<8}  {} file(s)",
        "",
        rar.list().len()
    );

    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: rar i <archive.rar>".into());
    }
    let rar = rar5::RarArchive::open(&args[0]).map_err(|e| format!("{e}"))?;

    let files: Vec<_> = rar.list().iter().filter(|e| !e.is_dir()).collect();
    let dirs: Vec<_> = rar.list().iter().filter(|e| e.is_dir()).collect();
    let total_size: u64 = files.iter().map(|e| e.size()).sum();
    let total_packed: u64 = files.iter().map(|e| e.compressed_size()).sum();

    println!("Archive: {}", args[0]);
    println!("Files:   {}", files.len());
    println!("Dirs:    {}", dirs.len());
    println!("Size:    {} bytes", total_size);
    println!("Packed:  {} bytes", total_packed);
    if total_size > 0 {
        println!(
            "Ratio:   {:.1}%",
            total_packed as f64 / total_size as f64 * 100.0
        );
    }

    Ok(())
}
