use crate::blockchain::OperationCode;
use rocket::get;
use rocket::serde::json::Json;

pub mod bill;
pub mod contacts;
pub mod identity;
pub mod quotes;

#[get("/")]
pub async fn exit() {
    std::process::exit(0x0100);
}

#[get("/return")]
pub async fn return_operation_codes() -> Json<Vec<OperationCode>> {
    Json(OperationCode::get_all_operation_codes())
}
