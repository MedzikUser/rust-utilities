use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

impl Claims {
    /// Generate Json Web Token Claims
    /// ```
    /// use rust_utilities::crypto::jsonwebtoken::Claims;
    ///
    /// let user_id = "123".to_string();
    /// let claims = Claims::new(user_id);
    /// ```
    pub fn new(sub: String) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(24);

        Self {
            sub,
            iat: iat.timestamp(),
            exp: exp.timestamp(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Token {
    header: Header,
    pub claims: Claims,
    pub encoded: String,
}

impl Token {
    /// Generate new token
    /// ```
    /// use rust_utilities::crypto::jsonwebtoken::{Token, Claims};
    ///
    /// let secret = b"secret";
    ///
    /// let claims = Claims::new("user_id_1234".to_string());
    /// let token = Token::new(secret, claims).unwrap();
    /// ```
    pub fn new(key: &[u8], claims: Claims) -> Result<Self, Error> {
        let header = Header::new(Algorithm::HS256);
        let encoded = encode(&header, &claims, &EncodingKey::from_secret(key))?;

        Ok(Self {
            header,
            claims,
            encoded,
        })
    }

    /// Validate token
    /// ```
    /// use rust_utilities::crypto::jsonwebtoken::{Token, Claims};
    ///
    /// let secret = b"secret";
    ///
    /// let claims = Claims::new("user_id_1234".to_string());
    /// let token = Token::new(secret, claims).unwrap();
    /// let decoded = Token::decode(secret, token.encoded).unwrap();
    /// ```
    pub fn decode(key: &[u8], token: String) -> Result<TokenData<Claims>, Error> {
        decode::<Claims>(
            &token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::{Claims, Token};

    #[test]
    fn decode_token_invalid_secret() {
        let key = b"key";
        let token = Token::new(key, Claims::new("test".to_string())).expect("generate token");

        let other_key = b"other key";

        let err = Token::decode(other_key, token.encoded).unwrap_err();

        assert_eq!(err.to_string(), "InvalidSignature");
    }
}
