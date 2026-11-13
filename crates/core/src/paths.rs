//! Soft BIP32 path lists for reconstruct, including compact ranges.
//!
//! A single `--path` / textarea line may be:
//! - `m` or `m/0/1` — one path
//! - `m/0..49` — `m/0` … `m/49` (inclusive)
//! - `m/0..m/49` — same, with an explicit end path
//!
//! At most [`MAX_DERIVATION_PATHS`] paths may be produced by one reconstruct.

use anyhow::{bail, Result};

/// Inclusive upper bound on how many keys one reconstruct may emit.
pub const MAX_DERIVATION_PATHS: usize = 50;

/// Expand path specs (literals and `..` ranges) into concrete soft paths.
/// Empty input defaults to `["m"]`.
pub fn expand_derivation_paths(specs: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for spec in specs {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            continue;
        }
        for path in expand_one(trimmed)? {
            if out.len() >= MAX_DERIVATION_PATHS {
                bail!(
                    "at most {MAX_DERIVATION_PATHS} derivation paths per reconstruct \
                     (split into multiple runs if you need more)"
                );
            }
            out.push(path);
        }
    }
    if out.is_empty() {
        out.push("m".to_string());
    }
    Ok(out)
}

fn expand_one(spec: &str) -> Result<Vec<String>> {
    let Some((left, right)) = spec.split_once("..") else {
        validate_soft_path(spec)?;
        return Ok(vec![spec.to_string()]);
    };
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || right.is_empty() {
        bail!("invalid path range `{spec}`: expected start..end");
    }

    let (prefix, start) = split_index(left)?;
    let end = if right.bytes().all(|b| b.is_ascii_digit()) {
        right
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("invalid path range end `{right}`"))?
    } else {
        let (end_prefix, end_idx) = split_index(right)?;
        if end_prefix != prefix {
            bail!(
                "path range `{spec}`: both ends must share the same parent \
                 (got `{prefix}` vs `{end_prefix}`)"
            );
        }
        end_idx
    };

    if end < start {
        bail!("path range `{spec}`: end index {end} is before start {start}");
    }
    let count = (end - start) as usize + 1;
    if count > MAX_DERIVATION_PATHS {
        bail!(
            "path range `{spec}` expands to {count} paths; \
             at most {MAX_DERIVATION_PATHS} allowed"
        );
    }

    Ok((start..=end)
        .map(|i| {
            if prefix.is_empty() || prefix == "m" {
                format!("m/{i}")
            } else {
                format!("{prefix}/{i}")
            }
        })
        .collect())
}

/// `m/0/1` → (`m/0`, 1); `m/0` → (`m`, 0).
fn split_index(path: &str) -> Result<(String, u32)> {
    validate_soft_path(path)?;
    let Some((parent, last)) = path.rsplit_once('/') else {
        bail!("path range start `{path}` must end in a numeric index (e.g. m/0)");
    };
    if !last.bytes().all(|b| b.is_ascii_digit()) {
        bail!("path range `{path}`: last component must be a decimal index");
    }
    let idx: u32 = last
        .parse()
        .map_err(|_| anyhow::anyhow!("path index `{last}` is out of range"))?;
    Ok((parent.to_string(), idx))
}

fn validate_soft_path(path: &str) -> Result<()> {
    if path.contains('\'') || path.contains('h') {
        bail!("hardened paths are not supported (`{path}`)");
    }
    if !path.starts_with('m') {
        bail!("derivation path must start with `m` (`{path}`)");
    }
    for (i, part) in path.split('/').enumerate() {
        if i == 0 {
            if part != "m" {
                bail!("derivation path must start with `m` (`{path}`)");
            }
            continue;
        }
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            bail!("invalid soft path `{path}`");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_default() {
        assert_eq!(
            expand_derivation_paths(&[String::from("m"), String::from("m/0")]).unwrap(),
            vec!["m", "m/0"]
        );
        assert_eq!(expand_derivation_paths(&[]).unwrap(), vec!["m"]);
    }

    #[test]
    fn short_and_long_range() {
        assert_eq!(
            expand_derivation_paths(&[String::from("m/0..2")]).unwrap(),
            vec!["m/0", "m/1", "m/2"]
        );
        assert_eq!(
            expand_derivation_paths(&[String::from("m/0..m/2")]).unwrap(),
            vec!["m/0", "m/1", "m/2"]
        );
        assert_eq!(
            expand_derivation_paths(&[String::from("m/0/0..1")]).unwrap(),
            vec!["m/0/0", "m/0/1"]
        );
    }

    #[test]
    fn rejects_oversize_and_hardened() {
        let err = expand_derivation_paths(&[String::from("m/0..50")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("51 paths") || err.contains("at most 50"),
            "{err}"
        );
        assert!(expand_derivation_paths(&[String::from("m/0'")]).is_err());
    }
}
