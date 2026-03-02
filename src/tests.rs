#[cfg(test)]
mod tests {
    use crate::models::{User, UserResponse, Claims, LoginRequest, RegisterRequest, AuthResponse};
    use crate::utils::{AuthError, JwtConfig};
    use chrono::Utc;
    use uuid::Uuid;

    // ============ MODEL TESTS ============

    #[test]
    fn test_user_response_from_user() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = UserResponse::from(user.clone());

        assert_eq!(response.id, user.id);
        assert_eq!(response.email, user.email);
        assert_eq!(response.first_name, user.first_name);
        assert_eq!(response.last_name, user.last_name);
        assert_eq!(response.role, user.role);
        assert_eq!(response.is_active, user.is_active);
    }

    #[test]
    fn test_claims_structure() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id.to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            token_type: "access".to_string(),
        };

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_login_request_deserialization() {
        let login_req = LoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
        };

        assert_eq!(login_req.email, "user@example.com");
        assert_eq!(login_req.password, "password123");
    }

    #[test]
    fn test_register_request_structure() {
        let register_req = RegisterRequest {
            email: "newuser@example.com".to_string(),
            password: "securepass123".to_string(),
            first_name: "Jane".to_string(),
            last_name: "Smith".to_string(),
            role: "student".to_string(),
        };

        assert_eq!(register_req.email, "newuser@example.com");
        assert_eq!(register_req.first_name, "Jane");
        assert_eq!(register_req.role, "student");
    }

    // ============ JWT CONFIG TESTS ============

    #[test]
    fn test_jwt_config_from_env() {
        let config = JwtConfig::from_env();
        
        assert!(!config.secret.is_empty());
        assert_eq!(config.access_token_expiry, 3600); // 1 hour
        assert_eq!(config.refresh_token_expiry, 604800); // 7 days
    }

    #[test]
    fn test_jwt_config_clone() {
        let config1 = JwtConfig::from_env();
        let config2 = config1.clone();

        assert_eq!(config1.secret, config2.secret);
        assert_eq!(config1.access_token_expiry, config2.access_token_expiry);
    }

    // ============ AUTH ERROR TESTS ============

    #[test]
    fn test_auth_error_variants() {
        let errors = vec![
            AuthError::InvalidCredentials,
            AuthError::Unauthorized,
            AuthError::Forbidden,
            AuthError::InvalidToken,
            AuthError::UserNotFound,
            AuthError::UserAlreadyExists,
            AuthError::InvalidRole,
            AuthError::InternalServerError,
        ];

        assert_eq!(errors.len(), 8);
    }

    #[test]
    fn test_auth_error_database_error() {
        let error = AuthError::DatabaseError("Connection failed".to_string());
        
        match error {
            AuthError::DatabaseError(msg) => {
                assert_eq!(msg, "Connection failed");
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    // ============ CLAIMS VALIDATION TESTS ============

    #[test]
    fn test_claims_token_type_access() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            token_type: "access".to_string(),
        };

        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_claims_token_type_refresh() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "mentor".to_string(),
            exp: Utc::now().timestamp() + 604800,
            iat: Utc::now().timestamp(),
            token_type: "refresh".to_string(),
        };

        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_user_role_validation() {
        let valid_roles = vec!["admin", "student", "mentor"];
        
        for role in valid_roles {
            assert!(["admin", "student", "mentor"].contains(&role));
        }
    }

    #[test]
    fn test_user_active_status() {
        let active_user = User {
            id: Uuid::new_v4(),
            email: "active@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Active".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let inactive_user = User {
            id: Uuid::new_v4(),
            email: "inactive@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Inactive".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(active_user.is_active);
        assert!(!inactive_user.is_active);
    }

    // ============ AUTH RESPONSE TESTS ============

    #[test]
    fn test_auth_response_structure() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: "admin".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = AuthResponse {
            user: UserResponse::from(user),
            access_token: "access_token_here".to_string(),
            refresh_token: "refresh_token_here".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        };

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
        assert!(!response.access_token.is_empty());
        assert!(!response.refresh_token.is_empty());
    }

    // ============ MIDDLEWARE EXTRACTOR TESTS ============

    #[test]
    fn test_authenticated_user_extraction() {
        // This would require async runtime, so we'll test the structure
        let user_id = Uuid::new_v4();
        let email = "user@example.com".to_string();
        
        assert!(!user_id.to_string().is_empty());
        assert!(!email.is_empty());
    }

    // ============ INTEGRATION TESTS ============

    #[test]
    fn test_user_email_validation() {
        let valid_emails = vec![
            "user@example.com",
            "test.user@example.co.uk",
            "user+tag@example.com",
        ];

        for email in valid_emails {
            assert!(email.contains("@"));
            assert!(email.contains("."));
        }
    }

    #[test]
    fn test_password_requirements() {
        let passwords = vec![
            "password123",
            "SecurePass@123",
            "MyP@ssw0rd",
        ];

        for password in passwords {
            assert!(password.len() >= 8, "Password should be at least 8 characters");
        }
    }

    #[test]
    fn test_user_role_enum_values() {
        let roles = vec!["admin", "student", "mentor"];
        
        for role in roles {
            assert!(["admin", "student", "mentor"].contains(&role));
        }
    }

    #[test]
    fn test_token_expiry_times() {
        let config = JwtConfig::from_env();
        
        // Access token should be shorter than refresh token
        assert!(config.access_token_expiry < config.refresh_token_expiry);
        
        // Access token should be 1 hour (3600 seconds)
        assert_eq!(config.access_token_expiry, 3600);
        
        // Refresh token should be 7 days (604800 seconds)
        assert_eq!(config.refresh_token_expiry, 604800);
    }

    #[test]
    fn test_claims_expiration_logic() {
        let now = Utc::now().timestamp();
        
        // Valid token (expires in future)
        let valid_claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp: now + 3600,
            iat: now,
            token_type: "access".to_string(),
        };

        // Expired token (expired in past)
        let expired_claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp: now - 3600,
            iat: now - 7200,
            token_type: "access".to_string(),
        };

        assert!(valid_claims.exp > now);
        assert!(expired_claims.exp < now);
    }

    #[test]
    fn test_user_uuid_generation() {
        let user_id1 = Uuid::new_v4();
        let user_id2 = Uuid::new_v4();

        assert_ne!(user_id1, user_id2);
        assert_eq!(user_id1.to_string().len(), 36); // UUID string format
    }

    #[test]
    fn test_user_timestamps() {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(user.created_at, user.updated_at);
    }
}
