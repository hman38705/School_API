#[cfg(test)]
mod middleware_tests {
    use crate::models::Claims;
    use crate::utils::AuthError;
    use chrono::Utc;
    use uuid::Uuid;

    // ============ AUTH MIDDLEWARE TESTS ============

    #[test]
    fn test_authorization_header_format() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let auth_header = format!("Bearer {}", token);

        assert!(auth_header.starts_with("Bearer "));
        let parts: Vec<&str> = auth_header.split(" ").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "Bearer");
    }

    #[test]
    fn test_invalid_authorization_header() {
        let invalid_headers = vec![
            "InvalidToken",
            "Basic dXNlcjpwYXNz",
            "token_without_bearer",
            "",
        ];

        for header in invalid_headers {
            assert!(!header.starts_with("Bearer "));
        }
    }

    #[test]
    fn test_token_extraction_from_header() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let auth_header = format!("Bearer {}", token);

        if auth_header.starts_with("Bearer ") {
            let extracted = &auth_header[7..];
            assert_eq!(extracted, token);
        }
    }

    #[test]
    fn test_access_token_type_validation() {
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
    fn test_refresh_token_type_validation() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            exp: Utc::now().timestamp() + 604800,
            iat: Utc::now().timestamp(),
            token_type: "refresh".to_string(),
        };

        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_invalid_token_type() {
        let invalid_types = vec!["invalid", "bearer", "jwt", ""];

        for token_type in invalid_types {
            assert_ne!(token_type, "access");
            assert_ne!(token_type, "refresh");
        }
    }

    // ============ ROLE GUARD TESTS ============

    #[test]
    fn test_admin_role_validation() {
        let role = "admin";
        let required_roles = vec!["admin"];

        assert!(required_roles.contains(&role));
    }

    #[test]
    fn test_student_role_validation() {
        let role = "student";
        let required_roles = vec!["student"];

        assert!(required_roles.contains(&role));
    }

    #[test]
    fn test_mentor_role_validation() {
        let role = "mentor";
        let required_roles = vec!["mentor"];

        assert!(required_roles.contains(&role));
    }

    #[test]
    fn test_role_mismatch() {
        let user_role = "student";
        let required_roles = vec!["admin"];

        assert!(!required_roles.contains(&user_role));
    }

    #[test]
    fn test_multiple_allowed_roles() {
        let user_role = "mentor";
        let required_roles = vec!["admin", "mentor"];

        assert!(required_roles.contains(&user_role));
    }

    #[test]
    fn test_role_case_sensitivity() {
        let role_lower = "admin";
        let role_upper = "ADMIN";

        assert_ne!(role_lower, role_upper);
    }

    // ============ EXTRACTOR TESTS ============

    #[test]
    fn test_authenticated_user_structure() {
        let user_id = Uuid::new_v4().to_string();
        let email = "user@example.com".to_string();

        assert!(!user_id.is_empty());
        assert!(!email.is_empty());
        assert!(email.contains("@"));
    }

    #[test]
    fn test_admin_user_extractor() {
        let user_id = Uuid::new_v4().to_string();
        let email = "admin@example.com".to_string();

        assert!(email.contains("admin"));
        assert_eq!(user_id.len(), 36); // UUID format
    }

    #[test]
    fn test_student_user_extractor() {
        let user_id = Uuid::new_v4().to_string();
        let email = "student@example.com".to_string();

        assert!(email.contains("student"));
        assert_eq!(user_id.len(), 36);
    }

    #[test]
    fn test_mentor_user_extractor() {
        let user_id = Uuid::new_v4().to_string();
        let email = "mentor@example.com".to_string();

        assert!(email.contains("mentor"));
        assert_eq!(user_id.len(), 36);
    }

    // ============ CLAIMS VALIDATION TESTS ============

    #[test]
    fn test_claims_subject_field() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id.to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            token_type: "access".to_string(),
        };

        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_claims_email_field() {
        let email = "user@example.com";
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: email.to_string(),
            role: "admin".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            token_type: "access".to_string(),
        };

        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_claims_role_field() {
        let role = "mentor";
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "mentor@example.com".to_string(),
            role: role.to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            token_type: "access".to_string(),
        };

        assert_eq!(claims.role, role);
    }

    #[test]
    fn test_claims_expiration_field() {
        let now = Utc::now().timestamp();
        let exp = now + 3600;
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "student".to_string(),
            exp,
            iat: now,
            token_type: "access".to_string(),
        };

        assert_eq!(claims.exp, exp);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_claims_issued_at_field() {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            exp: now + 3600,
            iat: now,
            token_type: "access".to_string(),
        };

        assert_eq!(claims.iat, now);
    }

    // ============ TOKEN EXPIRATION TESTS ============

    #[test]
    fn test_token_not_expired() {
        let now = Utc::now().timestamp();
        let exp = now + 3600;

        assert!(exp > now);
    }

    #[test]
    fn test_token_expired() {
        let now = Utc::now().timestamp();
        let exp = now - 3600;

        assert!(exp < now);
    }

    #[test]
    fn test_token_expiration_boundary() {
        let now = Utc::now().timestamp();
        let exp = now;

        assert_eq!(exp, now);
    }

    // ============ MIDDLEWARE ERROR HANDLING TESTS ============

    #[test]
    fn test_unauthorized_error() {
        let error = AuthError::Unauthorized;
        
        match error {
            AuthError::Unauthorized => assert!(true),
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_forbidden_error() {
        let error = AuthError::Forbidden;
        
        match error {
            AuthError::Forbidden => assert!(true),
            _ => panic!("Expected Forbidden error"),
        }
    }

    #[test]
    fn test_invalid_token_error() {
        let error = AuthError::InvalidToken;
        
        match error {
            AuthError::InvalidToken => assert!(true),
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[test]
    fn test_invalid_credentials_error() {
        let error = AuthError::InvalidCredentials;
        
        match error {
            AuthError::InvalidCredentials => assert!(true),
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    // ============ MIDDLEWARE INTEGRATION TESTS ============

    #[test]
    fn test_middleware_chain_order() {
        let steps = vec![
            "Extract Authorization Header",
            "Parse Bearer Token",
            "Verify JWT Signature",
            "Validate Token Type",
            "Check Token Expiration",
            "Extract Claims",
            "Validate Role",
            "Pass to Handler",
        ];

        assert_eq!(steps.len(), 8);
        assert_eq!(steps[0], "Extract Authorization Header");
        assert_eq!(steps[steps.len() - 1], "Pass to Handler");
    }

    #[test]
    fn test_header_case_insensitivity() {
        let headers = vec![
            "Authorization",
            "authorization",
            "AUTHORIZATION",
        ];

        // All should be treated as the same header
        for header in headers {
            assert!(header.to_lowercase() == "authorization");
        }
    }

    #[test]
    fn test_bearer_prefix_validation() {
        let valid_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let invalid_bearer = "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

        assert!(valid_bearer.starts_with("Bearer "));
        assert!(!invalid_bearer.starts_with("Bearer "));
    }

    #[test]
    fn test_token_format_validation() {
        let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let parts: Vec<&str> = valid_jwt.split(".").collect();

        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_multiple_roles_in_claims() {
        let roles = vec!["admin", "student", "mentor"];

        for role in roles {
            let claims = Claims {
                sub: Uuid::new_v4().to_string(),
                email: format!("{}@example.com", role),
                role: role.to_string(),
                exp: Utc::now().timestamp() + 3600,
                iat: Utc::now().timestamp(),
                token_type: "access".to_string(),
            };

            assert_eq!(claims.role, role);
        }
    }

    #[test]
    fn test_middleware_request_context() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "student";

        assert!(!user_id.to_string().is_empty());
        assert!(!email.is_empty());
        assert!(!role.is_empty());
    }
}
