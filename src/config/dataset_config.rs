#[derive(Clone)]
pub struct DatasetConfig {
    pub ports_dataset_path: String,
}

impl Default for DatasetConfig {
    fn default() -> Self {
        Self {
ports_dataset_path: "datasets/service-names-port-numbers.csv".to_string(),        }
    }
}
