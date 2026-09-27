pub mod model;
pub(crate) mod normalize;
pub mod parser;
pub mod path_mapper;

pub use model::SarifLog;
pub use normalize::{normalize_log, normalize_log_with_scanner};
pub use parser::{parse_sarif, MAX_SARIF_BYTES};

pub mod streaming;
