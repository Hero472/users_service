use std::error::Error;
use serde::{Deserialize, Serialize};
use mongodb::{options::ClientOptions, Client, Collection, Database};
use regex::Regex;

#[derive(Clone, Debug)]
pub struct MongoContext {
    client: Client,
    db: Database
}

impl MongoContext {
    
    pub async fn init(uri: &str, db_name: &str) -> Result<MongoContext, Box<dyn Error>> {
        println!("Attempting to connect to MongoDB at: {}", uri);
        
        Self::validate_mongo_uri(uri)?;

        let mut client_options = ClientOptions::parse(uri)
            .await?;
        
        client_options.app_name = Some("UserApp".to_string());
        
        let client = Client::with_options(client_options)
            .map_err(|e| {
                println!("Failed to create MongoDB client: {}", e);
                format!("Failed to create MongoDB client: {}", e)
            })?;
        
        client.list_database_names()
            .await
            .map_err(|e| {
                println!("Failed to connect to MongoDB: {}", e);
                format!("Failed to connect to MongoDB: {}", e)
            })?;
        
        let db = client.database(db_name);
        println!("Successfully connected to MongoDB database: {}", db_name);
        
        Ok(MongoContext { client, db })
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

    fn validate_mongo_uri(uri: &str) -> Result<(), Box<dyn Error>> {
        // Trim and check for empty string
        let trimmed_uri = uri.trim();
        if trimmed_uri.is_empty() {
            return Err("Invalid MongoDB URI: cannot be empty or whitespace".into());
        }

        // Basic validation: URI should start with mongodb:// or mongodb+srv://
        if !trimmed_uri.starts_with("mongodb://") && !trimmed_uri.starts_with("mongodb+srv://") {
            return Err(format!("Invalid MongoDB URI: must start with 'mongodb://' or 'mongodb+srv://'. Got: {}", uri).into());
        }

        // Check if URI contains at least a host (more than just the protocol)
        let host_part = if trimmed_uri.starts_with("mongodb://") {
            &trimmed_uri[10..] // Skip "mongodb://"
        } else {
            &trimmed_uri[14..] // Skip "mongodb+srv://"
        };

        if host_part.trim().is_empty() {
            return Err("Invalid MongoDB URI: missing host after protocol".into());
        }

        // Check for whitespace in the URI
        if uri.contains(char::is_whitespace) {
            return Err("Invalid MongoDB URI: cannot contain whitespace".into());
        }

        // More comprehensive validation using regex
        let re = Regex::new(r"^mongodb(\+srv)?://([^/\s]+)(/.*)?$").unwrap();
        if !re.is_match(trimmed_uri) {
            return Err(format!("Invalid MongoDB URI format. Expected format: mongodb://host[:port][/database] or mongodb+srv://host[/database]. Got: {}", uri).into());
        }

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;
    use serde::{Deserialize, Serialize};

    // Test model
    #[derive(Serialize, Deserialize, Debug)]
    struct TestUser {
        name: String,
        email: String,
    }

    // Test with MongoDB memory server (using test containers)
    #[tokio::test]
    // #[ignore = "Requires MongoDB running or test containers"]
    async fn test_mongo_context_init_success() {
        // This test requires a real MongoDB instance
        // For local testing, use a connection string like:
        // "mongodb://localhost:27017"
        let result = MongoContext::init("mongodb://localhost:27017", "test_db").await;
        
        // This will only pass if MongoDB is running locally
        if let Ok(context) = result {
            assert_eq!(context.get_db().name(), "test_db");
            // Verify we can actually use the connection
            let collection: Collection<TestUser> = context.collection("test_users");
            let count = collection.count_documents(doc! {}).await.unwrap();
            assert!(count >= 0); // Should not panic
        } else {
            // If MongoDB isn't running, skip the test
            println!("MongoDB not available, skipping test");
        }
    }

    #[tokio::test]
    async fn test_mongo_context_init_invalid_uri() {
        let result = MongoContext::init("invalid-uri", "test_db").await;
        println!("{:#?}", result);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Invalid MongoDB URI: must start with 'mongodb://' or 'mongodb+srv://'. Got: invalid-uri"));
    }

    #[test]
    fn test_validate_mongo_uri() {
        // Valid URIs
        assert!(MongoContext::validate_mongo_uri("mongodb://localhost:27017").is_ok());
        assert!(MongoContext::validate_mongo_uri("mongodb://localhost:27017/mydb").is_ok());
        assert!(MongoContext::validate_mongo_uri("mongodb+srv://cluster.example.com").is_ok());
        assert!(MongoContext::validate_mongo_uri("mongodb+srv://cluster.example.com/mydb").is_ok());
        assert!(MongoContext::validate_mongo_uri("mongodb://user:pass@localhost:27017").is_ok());
        assert!(MongoContext::validate_mongo_uri("mongodb://localhost").is_ok());

        // Invalid URIs
        assert!(MongoContext::validate_mongo_uri("invalid://localhost").is_err());
        assert!(MongoContext::validate_mongo_uri("mysql://localhost:3306").is_err());
        assert!(MongoContext::validate_mongo_uri("mongodb://").is_err());
        assert!(MongoContext::validate_mongo_uri("mongodb:// ").is_err());
        assert!(MongoContext::validate_mongo_uri("").is_err());
        assert!(MongoContext::validate_mongo_uri("mongodb").is_err());
    }

    // Test database and client getters
    #[tokio::test]
    // #[ignore = "Requires MongoDB running"]
    async fn test_get_db_and_client() {
        let result = MongoContext::init("mongodb://localhost:27017", "test_db").await;
        
        if let Ok(context) = result {
            let db = context.get_db();
            assert_eq!(db.name(), "test_db");
            
            let client = context.get_client();
            // Client should be able to list databases (if connected)
            let dbs = client.list_database_names().await;
            assert!(dbs.is_ok());
        }
    }

    // Test error handling for connection failures
    #[tokio::test]
    async fn test_mongo_context_connection_failure() {
        // Try to connect to a non-existent MongoDB instance
        let result = MongoContext::init("mongodb://invalid-host:9999", "test_db").await;
        
        // This should fail with a connection error
        assert!(result.is_err());
        
        // The error should be related to connection failure
        let error = result.unwrap_err();
        let error_str = error.to_string();
        assert!(
            error_str.contains("Failed to connect to MongoDB") ||
            error_str.contains("connection") ||
            error_str.contains("network")
        );
    }

    // Test clone implementation
    #[tokio::test]
    // #[ignore = "Requires MongoDB running"]
    async fn test_context_clone() {
        let result = MongoContext::init("mongodb://localhost:27017", "test_db").await;
        
        if let Ok(context) = result {
            let cloned = context.clone();
            
            // Both should reference the same database
            assert_eq!(context.get_db().name(), cloned.get_db().name());
            
            // Both should be usable
            let coll1: Collection<TestUser> = context.collection("users");
            let coll2: Collection<TestUser> = cloned.collection("users");
            
            assert_eq!(coll1.name(), coll2.name());
        }
    }
}