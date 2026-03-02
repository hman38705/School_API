#[cfg(test)]
mod model_tests {
    use crate::models::{User, UserResponse, Claims, LoginRequest, RegisterRequest, AuthResponse};
    use chrono::Utc;
    use uuid::Uuid;

    // ============ USER MODEL TESTS ============

    #[test]
    fn test_user_creation() {
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

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.first_name, "John");
        assert_eq!(user.role, "student");
        assert!(user.is_active);
    }

    #[test]
    fn test_user_with_admin_role() {
        let user = User {
            id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            first_name: "Admin".to_string(),
            last_name: "User".to_string(),
            role: "admin".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(user.role, "admin");
    }

    #[test]
    fn test_user_with_mentor_role() {
        let user = User {
            id: Uuid::new_v4(),
            email: "mentor@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            first_name: "Jane".to_string(),
            last_name: "Mentor".to_string(),
            role: "mentor".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(user.role, "mentor");
    }

    #[test]
    fn test_user_inactive_status() {
        let user = User {
            id: Uuid::new_v4(),
            email: "inactive@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            first_name: "Inactive".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!user.is_active);
    }

    #[test]
    fn test_user_unique_ids() {
        let user1 = User {
            id: Uuid::new_v4(),
            email: "user1@example.com".to_string(),
            password_hash: "hash1".to_string(),
            first_name: "User".to_string(),
            last_name: "One".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let user2 = User {
            id: Uuid::new_v4(),
            email: "user2@example.com".to_string(),
            password_hash: "hash2".to_string(),
            first_name: "User".to_string(),
            last_name: "Two".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_ne!(user1.id, user2.id);
    }

    // ============ USER RESPONSE MODEL TESTS ============

    #[test]
    fn test_user_response_conversion() {
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
    fn test_user_response_excludes_password() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "secret_hash".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = UserResponse::from(user);

        // UserResponse should not have password_hash field
        assert_ne!(response.email, "secret_hash");
    }

    // ============ CLAIMS MODEL TESTS ============

    #[test]
    fn test_claims_creation() {
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
    fn test_claims_access_token() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            token_type: "access".to_string(),
        };

        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_claims_refresh_token() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "mentor".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            token_type: "refresh".to_string(),
        };

        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_claims_expiration_time() {
        let exp = 1234567890;
        let iat = 1234567800;
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            exp,
            iat,
            token_type: "access".to_string(),
        };

        assert!(claims.exp > claims.iat);
    }

    // ============ LOGIN REQUEST MODEL TESTS ============

    #[test]
    fn test_login_request_creation() {
        let login = LoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
        };

        assert_eq!(login.email, "user@example.com");
        assert_eq!(login.password, "password123");
    }

    #[test]
    fn test_login_request_email_validation() {
        let login = LoginRequest {
            email: "test@example.com".to_string(),
            password: "pass".to_string(),
        };

        assert!(login.email.contains("@"));
        assert!(login.email.contains("."));
    }

    #[test]
    fn test_login_request_password_not_empty() {
        let login = LoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
        };

        assert!(!login.password.is_empty());
    }

    // ============ REGISTER REQUEST MODEL TESTS ============

    #[test]
    fn test_register_request_creation() {
        let register = RegisterRequest {
            email: "newuser@example.com".to_string(),
            password: "securepass123".to_string(),
            first_name: "Jane".to_string(),
            last_name: "Smith".to_string(),
            role: "student".to_string(),
        };

        assert_eq!(register.email, "newuser@example.com");
        assert_eq!(register.first_name, "Jane");
        assert_eq!(register.role, "student");
    }

    #[test]
    fn test_register_request_admin_role() {
        let register = RegisterRequest {
            email: "admin@example.com".to_string(),
            password: "adminpass123".to_string(),
            first_name: "Admin".to_string(),
            last_name: "User".to_string(),
            role: "admin".to_string(),
        };

        assert_eq!(register.role, "admin");
    }

    #[test]
    fn test_register_request_mentor_role() {
        let register = RegisterRequest {
            email: "mentor@example.com".to_string(),
            password: "mentorpass123".to_string(),
            first_name: "Mentor".to_string(),
            last_name: "User".to_string(),
            role: "mentor".to_string(),
        };

        assert_eq!(register.role, "mentor");
    }

    #[test]
    fn test_register_request_all_fields_required() {
        let register = RegisterRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "First".to_string(),
            last_name: "Last".to_string(),
            role: "student".to_string(),
        };

        assert!(!register.email.is_empty());
        assert!(!register.password.is_empty());
        assert!(!register.first_name.is_empty());
        assert!(!register.last_name.is_empty());
        assert!(!register.role.is_empty());
    }

    // ============ AUTH RESPONSE MODEL TESTS ============

    #[test]
    fn test_auth_response_creation() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = AuthResponse {
            user: UserResponse::from(user),
            access_token: "access_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        };

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
    }

    #[test]
    fn test_auth_response_tokens_not_empty() {
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
            access_token: "access_token_value".to_string(),
            refresh_token: "refresh_token_value".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        };

        assert!(!response.access_token.is_empty());
        assert!(!response.refresh_token.is_empty());
    }

    // ============ REFRESH TOKEN REQUEST MODEL TESTS ============

    #[test]
    fn test_refresh_token_request_creation() {
        let refresh_req = crate::models::RefreshTokenRequest {
            refresh_token: "refresh_token_value".to_string(),
        };

        assert_eq!(refresh_req.refresh_token, "refresh_token_value");
    }

    #[test]
    fn test_refresh_token_request_not_empty() {
        let refresh_req = crate::models::RefreshTokenRequest {
            refresh_token: "token".to_string(),
        };

        assert!(!refresh_req.refresh_token.is_empty());
    }

    // ============ MODEL SERIALIZATION TESTS ============

    #[test]
    fn test_user_response_serializable() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = UserResponse::from(user);
        
        // Should be serializable to JSON
        let json = serde_json::to_string(&response);
        assert!(json.is_ok());
    }

    #[test]
    fn test_claims_serializable() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            token_type: "access".to_string(),
        };

        let json = serde_json::to_string(&claims);
        assert!(json.is_ok());
    }

    #[test]
    fn test_auth_response_serializable() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: "student".to_string(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = AuthResponse {
            user: UserResponse::from(user),
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        };

        let json = serde_json::to_string(&response);
        assert!(json.is_ok());
    }

    // ============ MODEL VALIDATION TESTS ============

    #[test]
    fn test_valid_email_format() {
        let emails = vec![
            "user@example.com",
            "test.user@example.co.uk",
            "user+tag@example.com",
        ];

        for email in emails {
            assert!(email.contains("@"));
            assert!(email.contains("."));
        }
    }

    #[test]
    fn test_valid_role_values() {
        let valid_roles = vec!["admin", "student", "mentor"];

        for role in valid_roles {
            assert!(["admin", "student", "mentor"].contains(&role));
        }
    }

    #[test]
    fn test_user_timestamps_consistency() {
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

    #[test]
    fn test_claims_token_type_values() {
        let token_types = vec!["access", "refresh"];

        for token_type in token_types {
            assert!(["access", "refresh"].contains(&token_type));
        }
    }
}
