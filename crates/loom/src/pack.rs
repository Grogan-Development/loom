//! Language packs: detect Node/Python/Go/Rust and emit CI + runtime recipes.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Detected language pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    /// Node.js / TypeScript.
    Node,
    /// Python.
    Python,
    /// Go.
    Go,
    /// Rust / Cargo.
    Rust,
    /// Unknown; CI may still run `loom-ci.toml`.
    Unknown,
}

/// Runtime vs build image pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackPlan {
    /// Detected pack.
    pub kind: PackKind,
    /// Build/legacy runtime (may be older than LTS).
    pub build_image: String,
    /// Production LTS runtime after maintain cutover.
    pub runtime_image: String,
    /// Default test argv when `loom-ci.toml` is absent.
    pub test_command: Vec<String>,
    /// Default start argv when `loom-app.toml` is absent.
    pub start_command: Vec<String>,
    /// Default health path for web services.
    pub health_path: String,
    /// True when engines pin below current LTS.
    pub needs_legacy: bool,
}

/// Detects a pack from a materialized tree.
#[must_use]
pub fn detect(files: &BTreeMap<String, Vec<u8>>) -> PackKind {
    if files.contains_key("Cargo.toml") {
        PackKind::Rust
    } else if files.contains_key("go.mod") {
        PackKind::Go
    } else if files.contains_key("pyproject.toml")
        || files.contains_key("requirements.txt")
        || files.contains_key("setup.py")
        || files.contains_key("Pipfile")
    {
        PackKind::Python
    } else if files.contains_key("package.json") {
        PackKind::Node
    } else {
        PackKind::Unknown
    }
}

/// Builds a pack plan from a materialized tree.
#[must_use]
pub fn plan(files: &BTreeMap<String, Vec<u8>>) -> PackPlan {
    match detect(files) {
        PackKind::Node => node_plan(files),
        PackKind::Python => python_plan(files),
        PackKind::Go => PackPlan {
            kind: PackKind::Go,
            build_image: "golang:1.24-bookworm".to_owned(),
            runtime_image: "golang:1.24-bookworm".to_owned(),
            test_command: vec!["go".to_owned(), "test".to_owned(), "./...".to_owned()],
            start_command: vec!["go".to_owned(), "run".to_owned(), ".".to_owned()],
            health_path: "/healthz".to_owned(),
            needs_legacy: false,
        },
        PackKind::Rust => PackPlan {
            kind: PackKind::Rust,
            build_image: "rust:1.94-bookworm".to_owned(),
            runtime_image: "debian:bookworm-slim".to_owned(),
            test_command: vec![
                "cargo".to_owned(),
                "test".to_owned(),
                "--offline".to_owned(),
                "--quiet".to_owned(),
            ],
            start_command: vec!["/usr/local/bin/loomd".to_owned()],
            health_path: "/healthz".to_owned(),
            needs_legacy: false,
        },
        PackKind::Unknown => PackPlan {
            kind: PackKind::Unknown,
            build_image: "debian:bookworm-slim".to_owned(),
            runtime_image: "debian:bookworm-slim".to_owned(),
            test_command: vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "test -n \"$(ls -A)\"".to_owned(),
            ],
            start_command: Vec::new(),
            health_path: "/healthz".to_owned(),
            needs_legacy: false,
        },
    }
}

/// True when the tree looks deployable as an HTTP/worker app.
#[must_use]
pub fn looks_like_app(files: &BTreeMap<String, Vec<u8>>) -> bool {
    files.contains_key("loom-app.toml")
        || files.contains_key("Dockerfile")
        || files.contains_key("Procfile")
        || files.contains_key("package.json")
        || files.contains_key("go.mod")
        || files.contains_key("pyproject.toml")
        || files.contains_key("requirements.txt")
}

/// Infers start command from Procfile / package.json when toml is missing.
#[must_use]
pub fn infer_start(files: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    if let Some(procfile) = files.get("Procfile")
        && let Ok(text) = std::str::from_utf8(procfile)
    {
        for line in text.lines() {
            if let Some(cmd) = line.strip_prefix("web:") {
                return sh_words(cmd.trim());
            }
        }
    }
    if let Some(package) = files.get("package.json")
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(package)
    {
        if let Some(start) = value
            .pointer("/scripts/start")
            .and_then(serde_json::Value::as_str)
        {
            return sh_words(start);
        }
        if value.get("main").is_some() {
            return vec!["node".to_owned(), "index.js".to_owned()];
        }
        return vec!["npm".to_owned(), "start".to_owned()];
    }
    match detect(files) {
        PackKind::Python => vec!["python".to_owned(), "app.py".to_owned()],
        PackKind::Go => vec!["go".to_owned(), "run".to_owned(), ".".to_owned()],
        PackKind::Rust => vec!["/usr/local/bin/loomd".to_owned()],
        PackKind::Node => vec!["npm".to_owned(), "start".to_owned()],
        PackKind::Unknown => Vec::new(),
    }
}

fn node_plan(files: &BTreeMap<String, Vec<u8>>) -> PackPlan {
    let engines = node_engine(files);
    let needs_legacy = engines.is_some_and(|major| major < 22);
    let build = match engines {
        Some(18) => "node:18-bookworm",
        Some(20) => "node:20-bookworm",
        _ => "node:22-bookworm",
    };
    PackPlan {
        kind: PackKind::Node,
        build_image: build.to_owned(),
        runtime_image: "node:22-bookworm".to_owned(),
        test_command: vec!["npm".to_owned(), "test".to_owned()],
        start_command: infer_start(files),
        health_path: "/healthz".to_owned(),
        needs_legacy,
    }
}

fn python_plan(files: &BTreeMap<String, Vec<u8>>) -> PackPlan {
    let major_minor = python_requires(files);
    let needs_legacy = major_minor.is_some_and(|(major, minor)| major == 3 && minor < 12);
    let build = match major_minor {
        Some((3, 9)) => "python:3.9-bookworm",
        Some((3, 10)) => "python:3.10-bookworm",
        Some((3, 11)) => "python:3.11-bookworm",
        _ => "python:3.12-bookworm",
    };
    PackPlan {
        kind: PackKind::Python,
        build_image: build.to_owned(),
        runtime_image: "python:3.12-bookworm".to_owned(),
        test_command: vec![
            "python".to_owned(),
            "-m".to_owned(),
            "unittest".to_owned(),
            "discover".to_owned(),
        ],
        start_command: infer_start(files),
        health_path: "/healthz".to_owned(),
        needs_legacy,
    }
}

fn node_engine(files: &BTreeMap<String, Vec<u8>>) -> Option<u32> {
    if let Some(nvmrc) = files.get(".nvmrc")
        && let Ok(text) = std::str::from_utf8(nvmrc)
    {
        return parse_major(text.trim());
    }
    let package = files.get("package.json")?;
    let value = serde_json::from_slice::<serde_json::Value>(package).ok()?;
    let engines = value.get("engines")?.get("node")?.as_str()?;
    parse_major(engines)
}

fn python_requires(files: &BTreeMap<String, Vec<u8>>) -> Option<(u32, u32)> {
    let pyproject = files.get("pyproject.toml")?;
    let text = std::str::from_utf8(pyproject).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.split("requires-python").nth(1) {
            return parse_python_minor(rest);
        }
    }
    None
}

fn parse_major(value: &str) -> Option<u32> {
    let digits: String = value.chars().filter(char::is_ascii_digit).take(2).collect();
    digits.parse().ok()
}

fn parse_python_minor(value: &str) -> Option<(u32, u32)> {
    let mut parts = value
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>();
    if parts.starts_with('.') {
        parts = format!("3{parts}");
    }
    let mut split = parts.split('.');
    let major = split.next()?.parse().ok()?;
    let minor = split
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(12);
    Some((major, minor))
}

fn sh_words(command: &str) -> Vec<String> {
    command.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Pack-aware default test pipeline when `loom-ci.toml` is missing.
#[must_use]
pub fn default_test_command(root: &Path) -> Vec<String> {
    let mut files = BTreeMap::new();
    for name in [
        "Cargo.toml",
        "go.mod",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "Pipfile",
        "Procfile",
        "loom-app.toml",
        "Dockerfile",
        ".nvmrc",
    ] {
        if let Ok(bytes) = std::fs::read(root.join(name)) {
            files.insert(name.to_owned(), bytes);
        }
    }
    plan(&files).test_command
}
