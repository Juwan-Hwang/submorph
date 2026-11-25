//! Command-line front end.

use std::io::{Read, Write};
use std::process::ExitCode;

const USAGE: &str = "\
usage: submorph -t <mihomo|sing-box> [options] [INPUT]

Reads a subscription (Clash/Mihomo YAML or JSON, sing-box JSON, share links,
or Base64) from INPUT or stdin and writes the converted config to stdout.

options:
  -t, --target ID          mihomo or sing-box
  -o, --output FILE        write the config to FILE instead of stdout
      --provider NAME=FILE inline a rule provider's list (repeatable)
      --no-defaults        do not add a group, final rule or port to bare node lists
      --diagnostics FMT    text (default, to stderr), json (to stderr) or none
      --strict             exit with status 2 when any item was dropped
  -h, --help               show this help
  -V, --version            show the version";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("submorph: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let mut target = None;
    let mut input = None;
    let mut output = None;
    let mut diag_fmt = "text".to_string();
    let mut strict = false;
    let mut opts = submorph::ConvertOptions::default();
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("submorph {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "-t" | "--target" => target = Some(val(&a)?),
            "-o" | "--output" => output = Some(val(&a)?),
            "--diagnostics" => diag_fmt = val(&a)?,
            "--no-defaults" => opts.add_defaults = false,
            "--strict" => strict = true,
            "--provider" => {
                let v = val(&a)?;
                let (name, file) = v.split_once('=').ok_or("--provider expects NAME=FILE")?;
                let text = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
                opts.provider_contents.push((
                    name.to_string(),
                    String::from_utf8_lossy(&text).into_owned(),
                ));
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(format!("unknown option {s}\n\n{USAGE}"));
            }
            _ if input.is_none() => input = Some(a),
            _ => return Err("only one INPUT is accepted".into()),
        }
    }
    let target = target.ok_or_else(|| format!("missing --target\n\n{USAGE}"))?;
    let bytes = match input.as_deref() {
        None | Some("-") => {
            let mut b = Vec::new();
            std::io::stdin()
                .read_to_end(&mut b)
                .map_err(|e| e.to_string())?;
            b
        }
        Some(path) => std::fs::read(path).map_err(|e| format!("{path}: {e}"))?,
    };
    let res = submorph::convert_bytes(&bytes, &target, &opts).map_err(|e| e.to_string())?;
    match output {
        Some(path) => std::fs::write(&path, &res.output).map_err(|e| format!("{path}: {e}"))?,
        None => std::io::stdout()
            .write_all(res.output.as_bytes())
            .map_err(|e| e.to_string())?,
    }
    match diag_fmt.as_str() {
        "none" => {}
        "json" => {
            let list: Vec<_> = res.diagnostics.items.iter().map(|d| d.to_json()).collect();
            eprintln!("{}", serde_json::Value::Array(list));
        }
        _ => {
            for d in &res.diagnostics.items {
                eprintln!("{d}");
            }
        }
    }
    let dropped = res
        .diagnostics
        .items
        .iter()
        .any(|d| d.severity == submorph::Severity::Error);
    Ok(if strict && dropped {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}
