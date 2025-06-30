use actix_web::{post, web, HttpResponse, Result};
use solana_sdk::signature::{Keypair, Signer, Signature};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use spl_token::instruction as token_instruction;
use solana_sdk::bs58;
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
    println!("Generating new Solana keypair...");
    
    let keypair = Keypair::new();
    
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    println!("Generated keypair - Pubkey: {}", pubkey);
    
    let response_data = KeypairResponse {
        pubkey,
        secret,
    };
    
    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };
    
    println!("Sending keypair response");
    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/token/create")]
pub async fn create_token(request: Option<web::Json<CreateTokenRequest>>) -> Result<HttpResponse> {
    println!("Creating SPL token mint...");
    
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    println!("Request: mint_authority={}, mint={}, decimals={}", 
             request.mint_authority, request.mint, request.decimals);
    
    if request.mint_authority.is_empty() {
        println!("Error: Mint authority is required");
        return Ok(create_error_response("Missing required fields"));
    }

    if request.mint.is_empty() {
        println!("Error: Mint is required");
        return Ok(create_error_response("Missing required fields"));
    }

    if request.decimals > 9 {
        println!("Error: Decimals must be between 0 and 9");
        return Ok(create_error_response("Missing required fields"));
    }

    let mint_authority = match Pubkey::from_str(&request.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            println!("Error: Invalid mint authority public key");
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            println!("Error: Invalid mint public key");
            return Ok(create_error_response("Missing required fields"));
        }
    };

    println!("Creating initialize mint instruction...");
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        request.decimals,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            println!("Error: Failed to create initialize mint instruction");
            return Ok(create_error_response("Missing required fields"));
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
        instruction_data: bs58::encode(&instruction.data).into_string(),
    };

    println!("Created token mint successfully - Program ID: {}", response_data.program_id);
    println!("Sending create token response");

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/token/mint")]
pub async fn mint_token(request: Option<web::Json<MintTokenRequest>>) -> Result<HttpResponse> {
    println!("Minting SPL tokens...");
    
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    println!("Request: mint={}, destination={}, authority={}, amount={}", 
             request.mint, request.destination, request.authority, request.amount);
    
    if request.mint.is_empty() {
        println!("Error: Mint is required");
        return Ok(create_error_response("Missing required fields"));
    }

    if request.destination.is_empty() {
        println!("Error: Destination is required");
        return Ok(create_error_response("Missing required fields"));
    }

    if request.authority.is_empty() {
        println!("Error: Authority is required");
        return Ok(create_error_response("Missing required fields"));
    }

    if request.amount == 0 {
        println!("Error: Amount must be greater than 0");
        return Ok(create_error_response("Missing required fields"));
    }

    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            println!("Error: Invalid mint public key");
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            println!("Error: Invalid destination public key");
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let authority = match Pubkey::from_str(&request.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            println!("Error: Invalid authority public key");
            return Ok(create_error_response("Missing required fields"));
        }
    };

    println!("Creating mint-to instruction...");
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
            println!("Error: Failed to create mint-to instruction");
            return Ok(create_error_response("Missing required fields"));
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
        instruction_data: bs58::encode(&instruction.data).into_string(),
    };

    println!("Minted tokens successfully - Program ID: {}", response_data.program_id);
    println!("Sending mint token response");

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/message/sign")]
pub async fn sign_message(request: Option<web::Json<SignMessageRequest>>) -> Result<HttpResponse> {
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    if request.message.is_empty() || request.secret.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    let secret_bytes = match bs58::decode(&request.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response_data = SignMessageResponse {
        signature: bs58::encode(signature.as_ref()).into_string(),
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
pub async fn verify_message(request: Option<web::Json<VerifyMessageRequest>>) -> Result<HttpResponse> {
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    if request.message.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.signature.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.pubkey.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    let pubkey = match Pubkey::from_str(&request.pubkey) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let signature_bytes = match bs58::decode(&request.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
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
pub async fn send_sol(request: Option<web::Json<SendSolRequest>>) -> Result<HttpResponse> {
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    if request.from.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.to.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.lamports == 0 {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.lamports < 1000 {
        return Ok(create_error_response("Missing required fields"));
    }

    let from_pubkey = match Pubkey::from_str(&request.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let to_pubkey = match Pubkey::from_str(&request.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    if from_pubkey == to_pubkey {
        return Ok(create_error_response("Missing required fields"));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, request.lamports);

    let accounts: Vec<String> = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();

    let response_data = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: bs58::encode(&instruction.data).into_string(),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
}

#[post("/send/token")]
pub async fn send_token(request: Option<web::Json<SendTokenRequest>>) -> Result<HttpResponse> {
    let request = match request {
        Some(req) => req,
        None => {
            println!("Error: No request body provided");
            return Ok(create_error_response("Missing required fields"));
        }
    };
    
    if request.destination.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.mint.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.owner.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    if request.amount == 0 {
        return Ok(create_error_response("Missing required fields"));
    }

    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let _mint = match Pubkey::from_str(&request.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let owner = match Pubkey::from_str(&request.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Ok(create_error_response("Missing required fields"));
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
            return Ok(create_error_response("Missing required fields"));
        }
    };

    let accounts: Vec<TokenAccountMeta> = instruction.accounts.iter().map(|acc| TokenAccountMeta {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let response_data = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: bs58::encode(&instruction.data).into_string(),
    };

    let api_response = ApiResponse {
        success: true,
        data: Some(response_data),
        error: None,
    };

    Ok(HttpResponse::Ok().json(api_response))
} 