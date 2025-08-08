pub struct Pet {
    pub name: String,
    pub specie: String,
    pub breed: String,
    pub birth_date: Option<String>,
    pub color: Option<Vec<String>>,
    pub distinctive_features: Option<Vec<String>>,
    pub medical_conditions: Option<Vec<String>>,
    pub owner_id: Vec<u8>,
}

impl Pet {
    pub fn new(
        name: String,
        specie: String,
        breed: String,
        birth_date: Option<String>,
        color: Option<Vec<String>>,
        distinctive_features: Option<Vec<String>>,
        medical_conditions: Option<Vec<String>>,
        owner_id: Vec<u8>,
    ) -> Self {
        Pet {
            name,
            specie,
            breed,
            birth_date,
            color,
            distinctive_features,
            medical_conditions,
            owner_id,
        }
    }
}