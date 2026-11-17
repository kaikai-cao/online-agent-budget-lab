//! Long-lived JSON Lines service for the D11 E1 Coordinator (E1.0 §B).
//!
//! One JSON request per stdin line, one JSON response per stdout line. All
//! protocol responses go to stdout; diagnostics and startup errors go to
//! stderr. Trust configuration (including the Coordinator signing key) is
//! loaded from the config file path given as the first CLI argument — private
//! keys are never accepted in JSON Lines requests or as direct CLI values.

use std::{
    env, fs,
    io::{self, BufRead, Write},
    process::ExitCode,
};

use serde_json::json;

use d11_3_c_coordinator::e1::{
    error_response, handle_request, parse_service_config, parse_service_request, success_response,
    E1Coordinator,
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: e1_service <config.json>");
        return ExitCode::from(2);
    }
    let config_text = match fs::read_to_string(&args[1]) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot read config: {e}");
            return ExitCode::from(2);
        }
    };
    let config_value = match serde_json::from_str::<serde_json::Value>(&config_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid config JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let config = match parse_service_config(&config_value) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid service config: {e}");
            return ExitCode::from(2);
        }
    };
    let coordinator = match E1Coordinator::new(config.coordinator, config.db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("coordinator init failed: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!("e1_service ready");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match parse_service_request(&line) {
            Err(e) => error_response("", &e),
            Ok(request) => {
                let rid = request.request_id.clone();
                match handle_request(&coordinator, &request) {
                    Ok(result) => success_response(&rid, &result),
                    Err(e) => error_response(&rid, &e),
                }
            }
        };
        let response = response.unwrap_or_else(|e| {
            json!({"request_id": "", "ok": false,
                   "error": {"code": "STORE_ERROR", "message": e.to_string()}})
            .to_string()
        });
        if let Err(e) = writeln!(out, "{response}") {
            eprintln!("stdout write error: {e}");
            return ExitCode::FAILURE;
        }
        let _ = out.flush();
    }
    ExitCode::SUCCESS
}
