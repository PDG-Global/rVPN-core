use std::collections::HashMap;

fn main() {
    let mut map: HashMap<&str, &[&str]> = HashMap::new();
    map.insert("CN", rvpn_split_tunnel::builtin_domains::get_country_domains("CN").unwrap_or(&[]));
    map.insert("HK", rvpn_split_tunnel::builtin_domains::get_country_domains("HK").unwrap_or(&[]));
    map.insert("SG", rvpn_split_tunnel::builtin_domains::get_country_domains("SG").unwrap_or(&[]));
    map.insert("JP", rvpn_split_tunnel::builtin_domains::get_country_domains("JP").unwrap_or(&[]));
    map.insert("KR", rvpn_split_tunnel::builtin_domains::get_country_domains("KR").unwrap_or(&[]));
    map.insert("TW", rvpn_split_tunnel::builtin_domains::get_country_domains("TW").unwrap_or(&[]));

    let json_map: HashMap<&str, Vec<&str>> = map.into_iter()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_map).unwrap());
}
