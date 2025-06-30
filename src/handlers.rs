use actix_web::{post, web, HttpResponse, Result};
use solana_sdk::signature::{Keypair, Signer, Signature};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use spl_token::instruction as token_instruction;
use base64::{Engine, engine::general_purpose::STANDARD};
use crate::types::{ApiResponse, KeypairResponse, CreateTokenRequest, CreateTokenResponse, MintTokenRequest, MintTokenResponse, SignMessageRequest, SignMessageResponse, VerifyMessageRequest, VerifyMessageResponse, SendSolRequest, SendSolResponse, SendTokenRequest, SendTokenResponse, TokenMeta, TokenAccountMeta};
use std::str::FromStr;


fn create_error_response(error_message: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(ApiResponse::<()> {
        success: false,
        data: None,
        error: Some(error_message.to_string()),
    })
}

#[post("/keypair")]
pub async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    
    let pubkey = keypair.pubkey().to_string();
    
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    let response_data = KeypairResponse {
        pubkey,
        secret,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/token/create")]
pub async fn create_token(request: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    
    if request.mint_authority.is_empty() {
        return Ok(create_error_response("Mint authority is required"));
    }

    if request.mint.is_empty() {
        return Ok(create_error_response("Mint is required"));
    }

    if request.decimals > 9 {
        return Ok(create_error_response("Decimals must be between 0 and 9"));
    }

    let mint_authority = match Pubkey::from_str(&request.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid mint authority public key"));
        }
    };

    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid mint public key"));
        }
    };

    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        request.decimals,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return Ok(create_error_response("Failed to create initialize mint instruction"));
        }
    };

    let accounts: Vec<TokenMeta> = instruction.accounts.iter().map(|acc| TokenMeta {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let response_data = CreateTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: STANDARD.encode(&instruction.data),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/token/mint")]
pub async fn mint_token(request: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    
    if request.mint.is_empty() {
        return Ok(create_error_response("Mint is required"));
    }

    if request.destination.is_empty() {
        return Ok(create_error_response("Destination is required"));
    }

    if request.authority.is_empty() {
        return Ok(create_error_response("Authority is required"));
    }

    if request.amount == 0 {
        return Ok(create_error_response("Amount must be greater than 0"));
    }

    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid mint public key"));
        }
    };

    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid destination public key"));
        }
    };

    let authority = match Pubkey::from_str(&request.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid authority public key"));
        }
    };

    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        request.amount,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return Ok(create_error_response("Failed to create mint-to instruction"));
        }
    };

    let accounts: Vec<TokenMeta> = instruction.accounts.iter().map(|acc| TokenMeta {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let response_data = MintTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: STANDARD.encode(&instruction.data),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/message/sign")]
pub async fn sign_message(request: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    
    if request.message.is_empty() || request.secret.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    let secret_bytes = match bs58::decode(&request.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(create_error_response("Invalid secret key format"));
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => {
            return Ok(create_error_response("Invalid secret key"));
        }
    };

    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response_data = SignMessageResponse {
        signature: STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: request.message.clone(),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/message/verify")]
pub async fn verify_message(request: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    
    if request.message.is_empty() {
        return Ok(create_error_response("Message is required"));
    }

    if request.signature.is_empty() {
        return Ok(create_error_response("Signature is required"));
    }

    if request.pubkey.is_empty() {
        return Ok(create_error_response("Public key is required"));
    }

    let pubkey = match Pubkey::from_str(&request.pubkey) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid public key format"));
        }
    };

    let signature_bytes = match STANDARD.decode(&request.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(create_error_response("Invalid signature format"));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(create_error_response("Invalid signature"));
        }
    };

    let message_bytes = request.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response_data = VerifyMessageResponse {
        valid: is_valid,
        message: request.message.clone(),
        pubkey: request.pubkey.clone(),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/send/sol")]
pub async fn send_sol(request: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    
    if request.from.is_empty() {
        return Ok(create_error_response("From address is required"));
    }

    if request.to.is_empty() {
        return Ok(create_error_response("To address is required"));
    }

    if request.lamports == 0 {
        return Ok(create_error_response("Lamports must be greater than 0"));
    }

    if request.lamports < 1000 {
        return Ok(create_error_response("Minimum transfer amount is 1000 lamports (0.000001 SOL)"));
    }

    let from_pubkey = match Pubkey::from_str(&request.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid 'from' address: Must be a valid Solana public key (base58 encoded, 32 bytes)"));
        }
    };

    let to_pubkey = match Pubkey::from_str(&request.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid 'to' address: Must be a valid Solana public key (base58 encoded, 32 bytes)"));
        }
    };

    if from_pubkey == to_pubkey {
        return Ok(create_error_response("Cannot transfer to the same address"));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, request.lamports);

    let accounts: Vec<String> = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();

    let response_data = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: STANDARD.encode(&instruction.data),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/send/token")]
pub async fn send_token(request: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    
    if request.destination.is_empty() {
        return Ok(create_error_response("Destination address is required"));
    }

    if request.mint.is_empty() {
        return Ok(create_error_response("Mint address is required"));
    }

    if request.owner.is_empty() {
        return Ok(create_error_response("Owner address is required"));
    }

    if request.amount == 0 {
        return Ok(create_error_response("Amount must be greater than 0"));
    }

    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid 'destination' address: Pls provide a valid solana address"));
        }
    };

    let _mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid 'mint' address: Pls provide a valid solana address"));
        }
    };

    let owner = match Pubkey::from_str(&request.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Invalid 'owner' address: Pls provide a valid solana address"));
        }
    };

    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &owner,
        &destination,
        &owner,
        &[],
        request.amount,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return Ok(create_error_response("Failed to create transfer instruction"));
        }
    };

    let accounts: Vec<TokenAccountMeta> = instruction.accounts.iter().map(|acc| TokenAccountMeta {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let response_data = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: STANDARD.encode(&instruction.data),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
} 