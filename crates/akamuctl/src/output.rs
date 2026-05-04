//! Output formatting: table mode and JSON mode.

use serde_json::Value;

pub enum Format {
    Table,
    Json,
}

impl Format {
    pub fn from_str(s: &str) -> Self {
        if s == "json" {
            Format::Json
        } else {
            Format::Table
        }
    }
}

/// Print a JSON value according to the chosen format.
pub fn print(fmt: &Format, value: &Value) {
    match fmt {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
        }
        Format::Table => print_table(value),
    }
}

fn print_table(value: &Value) {
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                println!("(no results)");
                return;
            }
            // Collect all keys from the first object.
            if let Some(Value::Object(first)) = arr.first() {
                let keys: Vec<&str> = first.keys().map(|k| k.as_str()).collect();
                let col_widths: Vec<usize> = keys
                    .iter()
                    .map(|k| {
                        let max_val = arr
                            .iter()
                            .filter_map(|row| row.get(*k))
                            .map(|v| value_str(v).len())
                            .max()
                            .unwrap_or(0);
                        k.len().max(max_val)
                    })
                    .collect();
                // Header.
                let header: Vec<String> = keys
                    .iter()
                    .zip(&col_widths)
                    .map(|(k, w)| format!("{:<w$}", k, w = w))
                    .collect();
                println!("{}", header.join("  "));
                let sep: Vec<String> = col_widths.iter().map(|w| "-".repeat(*w)).collect();
                println!("{}", sep.join("  "));
                // Rows.
                for row in arr {
                    let cols: Vec<String> = keys
                        .iter()
                        .zip(&col_widths)
                        .map(|(k, w)| {
                            let v = row.get(*k).map(value_str).unwrap_or_default();
                            format!("{:<w$}", v, w = w)
                        })
                        .collect();
                    println!("{}", cols.join("  "));
                }
            } else {
                // Array of non-objects: print each on a line.
                for item in arr {
                    println!("{}", value_str(item));
                }
            }
        }
        Value::Object(map) => {
            let key_width = map.keys().map(|k| k.len()).max().unwrap_or(0);
            for (k, v) in map {
                println!("{:<key_width$}  {}", k, value_str(v), key_width = key_width);
            }
        }
        Value::Null => {}
        other => println!("{}", value_str(other)),
    }
}

fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
