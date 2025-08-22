use mongodb::{Client, options::ClientOptions, Database, Collection};
use std::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct MongoRepository {
    client: Client,
    db: Database
}

impl MongoRepository {
    
    pub async fn init(uri: &str, db_name: &str) -> Result<MongoRepository, Box<dyn Error>> {
        println!("Attempting to connect to MongoDB at: {}", uri);
        
        let mut client_options = ClientOptions::parse(uri).await.map_err(|e| {
            println!("Failed to parse MongoDB connection URI: {}", e);
            e
        })?;
        
        client_options.app_name = Some("PetsApp".to_string());
        
        let client = Client::with_options(client_options).map_err(|e| {
            println!("Failed to create MongoDB client: {}", e);
            e
        })?;
        
        // Test the connection
        client.list_database_names().await.map_err(|e| {
            println!("Failed to connect to MongoDB: {}", e);
            e
        })?;
        
        let db = client.database(db_name);
        println!("Successfully connected to MongoDB database: {}", db_name);
        
        Ok(MongoRepository { client, db })
    }

    pub fn get_db(&self) -> &Database {
        &self.db
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub fn collection<T>(&self, name: &str) -> Collection<T>
    where
        T: Send + Sync + Unpin + for<'de> Deserialize<'de> + Serialize,
    {
        self.db.collection::<T>(name)
    }

}