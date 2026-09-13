//! `dvpn-measure <baseline.csv> <defended.csv>`

use std::process::ExitCode;

use dvpn_measure::{Summary, parse, summarize, throughput};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: dvpn-measure <baseline.csv> <defended.csv>");
        return ExitCode::from(2);
    }

    let load = |path: &str| -> Result<Summary, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Ok(summarize(&parse(&text).map_err(|e| format!("{path}: {e}"))?))
    };

    let (base, def) = match (load(&args[0]), load(&args[1])) {
        (Ok(b), Ok(d)) => (b, d),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let row = |label: &str, a: String, b: String| println!("  {label:<26} {a:>14} {b:>14}");

    println!("\n  {:<26} {:>14} {:>14}", "", "UNDEFENDED", "DEFENDED");
    println!("  {}", "─".repeat(56));
    row("packets", base.packets.to_string(), def.packets.to_string());
    row("  sent / received", format!("{} / {}", base.sent, base.received), format!("{} / {}", def.sent, def.received));
    row("bytes", base.bytes.to_string(), def.bytes.to_string());
    row("duration (s)", format!("{:.1}", base.duration_ms as f64 / 1000.0), format!("{:.1}", def.duration_ms as f64 / 1000.0));
    println!("  {}", "─".repeat(56));
    row("distinct packet sizes", base.unique_sizes.to_string(), def.unique_sizes.to_string());
    row("size entropy (bits)", format!("{:.3}", base.size_entropy_bits), format!("{:.3}", def.size_entropy_bits));
    row("link occupancy", format!("{:.1}%", base.occupancy * 100.0), format!("{:.1}%", def.occupancy * 100.0));
    row("distinguishable bursts", base.bursts.to_string(), def.bursts.to_string());
    println!("  {}", "─".repeat(56));

    let bt = throughput(&base);
    let dt = throughput(&def);
    row("throughput (B/s)", format!("{bt:.0}"), format!("{dt:.0}"));
    if bt > 0.0 {
        println!("\n  Bandwidth cost      {:.2}x  ({:+.0}%)", dt / bt, (dt / bt - 1.0) * 100.0);
    }
    let pad_share = if def.packets > 0 {
        // Anything beyond the baseline's packet count is, to a first approximation, cover.
        (def.packets.saturating_sub(base.packets)) as f64 / def.packets as f64
    } else {
        0.0
    };
    println!("  Cover traffic       {:.0}% of defended packets", pad_share * 100.0);

    println!(
        "\n  Size entropy fell from {:.3} to {:.3} bits.{}",
        base.size_entropy_bits,
        def.size_entropy_bits,
        if def.unique_sizes == 1 { " Every datagram is identical in length." } else { "" }
    );
    println!(
        "\n  Not measured here: attacker classification accuracy. That needs a real\n  \
         multi-site trace corpus and a trained classifier. Size uniformity and\n  \
         occupancy are necessary conditions for a defense, not sufficient ones —\n  \
         a trace can be perfectly uniform in size and still leak through timing.\n"
    );
    ExitCode::SUCCESS
}
