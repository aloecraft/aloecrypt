use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=api.json");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("api.rs");
    let mut out = fs::File::create(&out_path).expect("failed to create api.rs");

    let raw = fs::read_to_string("api.json").expect("failed to read api.json");
    let api: serde_json::Value = serde_json::from_str(&raw).expect("failed to parse api.json");

    // sz_consts
    writeln!(out, "pub mod consts_api {{").unwrap();
    for c in api["sz_consts"].as_array().unwrap() {
        writeln!(
            out,
            "    pub const {} : usize = {};",
            c["name"].as_str().unwrap(),
            c["value"].as_str().unwrap(),
        )
        .unwrap();
    }

    for c in api["empty_consts"].as_array().unwrap() {
        writeln!(
            out,
            "    pub const {} : [u8; {}] = [0u8; {}];",
            c["name"].as_str().unwrap(),
            c["size"].as_str().unwrap(),
            c["size"].as_str().unwrap(),
        )
        .unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out, "use consts_api::*;").unwrap();

    writeln!(out).unwrap();

    writeln!(out, "pub mod types {{").unwrap();
    writeln!(out, "    use super::*;").unwrap();

    // byte_aliases
    for a in api["byte_aliases"].as_array().unwrap() {
        writeln!(
            out,
            "    pub type {} = [u8; {}];",
            a["name"].as_str().unwrap(),
            a["length"].as_str().unwrap(),
        )
        .unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use types::*;").unwrap();

    writeln!(out).unwrap();

    // models
    for ns_entry in api["models"].as_array().unwrap() {
        let namespace = ns_entry["namespace"].as_str().unwrap();

        writeln!(out, "pub mod {namespace} {{").unwrap();

        writeln!(out, "    use super::*;").unwrap();
        writeln!(out).unwrap();

        for (struct_name, model) in ns_entry["models"].as_object().unwrap() {
            let derives = model["derives"].as_str().unwrap();
            writeln!(out, "    #[derive({derives})]").unwrap();
            writeln!(out, "    pub struct {struct_name} {{").unwrap();

            for field in model["fields"].as_array().unwrap() {
                let prefix = field["prefix"].as_str().unwrap();
                let name = field["name"].as_str().unwrap();
                let mut ty = field["type"].as_str().unwrap().to_string();

                if field.get("optional").and_then(|v| v.as_str()) == Some("true") {
                    ty = format!("Option<{ty}>");
                }

                if prefix.is_empty() {
                    writeln!(out, "        pub {name}: {ty},").unwrap();
                } else {
                    // prefix already contains its own newline + indentation
                    write!(out, "{prefix}").unwrap();
                    writeln!(out, "        pub {name}: {ty},").unwrap();
                }
            }

            writeln!(out, "    }}").unwrap();
            writeln!(out).unwrap();
        }

        writeln!(out, "}}").unwrap();
        writeln!(out, "use {namespace}::*;").unwrap();
        writeln!(out).unwrap();
    }

    writeln!(out, "pub mod traits {{").unwrap();
    writeln!(out, " use super::*;").unwrap();

    for trait_entry in api["traits"].as_array().unwrap() {
        let trait_name = trait_entry["name"].as_str().unwrap();
        let generics = trait_entry["generics"].as_array().unwrap();

        // Build generic parameter string
        let generic_params: Vec<&str> = generics
            .iter()
            .filter_map(|g| g.as_str())
            .filter(|g| !g.is_empty())
            .collect();

        let generic_str = if generic_params.is_empty() {
            String::new()
        } else {
            format!("<{}>", generic_params.join(", "))
        };

        writeln!(out, "    pub trait {trait_name}{generic_str} {{").unwrap();

        for func in trait_entry["functions"].as_array().unwrap() {
            let fn_name = func["name"].as_str().unwrap();
            let instance = func["instance"].as_str().unwrap();
            let ret = func["return"].as_str().unwrap();
            let constraints = func.get("constraints").and_then(|v| v.as_str());

            let params = func["params"].as_array().unwrap();
            let param_str = params
                .iter()
                .filter(|p| {
                    p["name"].as_str().unwrap_or("").is_empty()
                        && p["type"].as_str().unwrap_or("").is_empty()
                })
                .count()
                .eq(&params.len())
                .then(|| String::new())
                .unwrap_or_else(|| {
                    params
                        .iter()
                        .filter(|p| !p["name"].as_str().unwrap_or("").is_empty())
                        .map(|p| {
                            format!(
                                "{}: {}",
                                p["name"].as_str().unwrap(),
                                p["type"].as_str().unwrap()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                });

            let full_params = if instance.is_empty() {
                param_str
            } else if param_str.is_empty() {
                instance.to_string()
            } else {
                format!("{instance}, {param_str}")
            };

            let where_clause = constraints
                .map(|c| format!(" where {c}"))
                .unwrap_or_default();

            writeln!(
                out,
                "        fn {fn_name}({full_params}) -> {ret}{where_clause};"
            )
            .unwrap();
        }

        writeln!(out, "    }}").unwrap();
        writeln!(out).unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out, "use traits::*;").unwrap();
}
