//! Output formatting: table mode and JSON mode.

use serde_json::Value;

pub enum Format {
    Table,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Format::Json),
            "table" => Ok(Format::Table),
            other => Err(format!(
                "unknown output format '{other}'; expected 'json' or 'table'"
            )),
        }
    }
}

/// Print a JSON value according to the chosen format.
pub fn print(fmt: &Format, value: &Value) {
    match fmt {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_default()
            );
        }
        Format::Table => print_table(value),
    }
}

fn print_table(value: &Value) {
    match value {
        Value::Array(arr) => print_array_table(arr),
        Value::Object(map) => {
            // If the object has exactly one array-valued field, render that
            // array as the table and print any remaining scalar fields as a footer.
            let array_keys: Vec<&str> = map
                .iter()
                .filter(|(_, v)| matches!(v, Value::Array(_)))
                .map(|(k, _)| k.as_str())
                .collect();
            if array_keys.len() == 1 {
                let key = array_keys[0];
                if let Some(Value::Array(arr)) = map.get(key) {
                    print_array_table(arr);
                }
                let scalars: Vec<(&str, &Value)> = map
                    .iter()
                    .filter(|(_, v)| !matches!(v, Value::Array(_)))
                    .map(|(k, v)| (k.as_str(), v))
                    .collect();
                if !scalars.is_empty() {
                    let key_width = scalars.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
                    for (k, v) in &scalars {
                        println!("{:<key_width$}  {}", k, value_str(v), key_width = key_width);
                    }
                }
            } else {
                let key_width = map.keys().map(|k| k.len()).max().unwrap_or(0);
                for (k, v) in map {
                    println!("{:<key_width$}  {}", k, value_str(v), key_width = key_width);
                }
            }
        }
        Value::Null => {}
        other => println!("{}", value_str(other)),
    }
}

fn print_array_table(arr: &[Value]) {
    if arr.is_empty() {
        println!("(no results)");
        return;
    }
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
        let header: Vec<String> = keys
            .iter()
            .zip(&col_widths)
            .map(|(k, w)| format!("{:<w$}", k, w = w))
            .collect();
        println!("{}", header.join("  "));
        let sep: Vec<String> = col_widths.iter().map(|w| "-".repeat(*w)).collect();
        println!("{}", sep.join("  "));
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
        for item in arr {
            println!("{}", value_str(item));
        }
    }
}

fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
