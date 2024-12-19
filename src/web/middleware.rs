use crate::service::ServiceContext;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Data, Request, Response};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct IdentityCheck;

#[rocket::async_trait]
impl Fairing for IdentityCheck {
    fn info(&self) -> Info {
        Info {
            name: "Identity Check Middleware",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if request.uri().path().starts_with("/identity") {
            return;
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if let Some(context) = request.rocket().state::<ServiceContext>() {
            if !context.identity_service.identity_exists().await {
                return response.set_status(Status::NotAcceptable);
            }
        }
    }
}
