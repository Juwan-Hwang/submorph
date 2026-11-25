//! Rule-set URL mapping between mihomo (`.mrs`/`.yaml`/`.list`) and sing-box
//! (`.srs`) builds of the same public lists, and geo database lookups.
//!
//! Only well-known public repositories are mapped: MetaCubeX/meta-rules-dat
//! (branches `meta` and `sing`), SagerNet/sing-geosite and SagerNet/sing-geoip
//! (branch `rule-set`). Anything else is reported rather than guessed.

/// sing-box rule-set URL for `GEOSITE,<name>`.
pub fn geosite_srs(name: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs",
        name.to_ascii_lowercase()
    )
}

/// sing-box rule-set URL for `GEOIP,<code>`.
pub fn geoip_srs(code: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs",
        code.to_ascii_lowercase()
    )
}

/// Maps a mihomo rule-provider URL from meta-rules-dat to the sing-box build.
pub fn mihomo_to_srs(url: &str) -> Option<String> {
    if !url.contains("meta-rules-dat") {
        return None;
    }
    let (stem, ext) = url.rsplit_once('.')?;
    if !matches!(ext, "mrs" | "yaml" | "yml" | "list" | "txt") {
        return None;
    }
    if !(stem.contains("/geo/") || stem.contains("/geo-lite/")) {
        return None;
    }
    let swapped = if stem.contains("/meta/geo") {
        stem.replacen("/meta/geo", "/sing/geo", 1)
    } else if stem.contains("@meta/") {
        stem.replacen("@meta/", "@sing/", 1)
    } else if stem.contains("/refs/heads/meta/") {
        stem.replacen("/refs/heads/meta/", "/refs/heads/sing/", 1)
    } else if stem.contains("/release/") {
        stem.replacen("/release/", "/sing/", 1)
    } else {
        return None;
    };
    Some(format!("{swapped}.srs"))
}

/// Maps a sing-box `.srs` URL back to the mihomo `.mrs` build of the same list.
pub fn srs_to_mrs(url: &str) -> Option<String> {
    let stem = url.strip_suffix(".srs")?;
    if stem.contains("meta-rules-dat") {
        let swapped = if stem.contains("/sing/geo") {
            stem.replacen("/sing/geo", "/meta/geo", 1)
        } else if stem.contains("@sing/") {
            stem.replacen("@sing/", "@meta/", 1)
        } else {
            return None;
        };
        return Some(format!("{swapped}.mrs"));
    }
    if let Some(name) = stem.rsplit('/').next() {
        if stem.contains("sing-geosite")
            && let Some(n) = name.strip_prefix("geosite-")
        {
            return Some(format!(
                "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{n}.mrs"
            ));
        }
        if stem.contains("sing-geoip")
            && let Some(n) = name.strip_prefix("geoip-")
        {
            return Some(format!(
                "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/{n}.mrs"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_meta_rules_dat() {
        assert_eq!(
            mihomo_to_srs("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.mrs").as_deref(),
            Some("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs")
        );
        assert_eq!(
            mihomo_to_srs(
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
            )
            .as_deref(),
            Some("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs")
        );
        assert_eq!(mihomo_to_srs("https://example.com/my.yaml"), None);
        assert_eq!(
            srs_to_mrs(&geosite_srs("cn")).as_deref(),
            Some(
                "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
            )
        );
    }
}
