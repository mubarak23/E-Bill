use super::super::data::{DeleteContactForm, EditContactForm, NewContactForm};
use crate::bill::contacts::{
    add_in_contacts_map, change_contact_name_from_contacts_map, delete_from_contacts_map,
    get_contacts_vec, Contact,
};
use crate::constants::IDENTITY_FILE_PATH;
use crate::dht::Client;
use rocket::form::Form;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{delete, get, post, put, State};
use std::path::Path;

#[get("/return")]
pub async fn return_contacts() -> Json<Vec<Contact>> {
    let contacts: Vec<Contact> = get_contacts_vec();
    Json(contacts)
}

#[delete("/remove", data = "<remove_contact_form>")]
pub async fn remove_contact(remove_contact_form: Form<DeleteContactForm>) -> Status {
    if !Path::new(IDENTITY_FILE_PATH).exists() {
        Status::NotAcceptable
    } else {
        delete_from_contacts_map(remove_contact_form.name.clone());

        Status::Ok
    }
}

#[post("/new", data = "<new_contact_form>")]
pub async fn new_contact(
    state: &State<Client>,
    new_contact_form: Form<NewContactForm>,
) -> Result<Json<Vec<Contact>>, Status> {
    if !Path::new(IDENTITY_FILE_PATH).exists() {
        Err(Status::NotAcceptable)
    } else {
        add_in_contacts_map(
            new_contact_form.name.clone(),
            new_contact_form.node_id.clone(),
            state.inner().clone(),
        )
        .await;

        Ok(Json(get_contacts_vec()))
    }
}

#[put("/edit", data = "<edit_contact_form>")]
pub async fn edit_contact(
    edit_contact_form: Form<EditContactForm>,
) -> Result<Json<Vec<Contact>>, Status> {
    if !Path::new(IDENTITY_FILE_PATH).exists() {
        Err(Status::NotAcceptable)
    } else {
        change_contact_name_from_contacts_map(
            edit_contact_form.old_name.clone(),
            edit_contact_form.name.clone(),
        );

        Ok(Json(get_contacts_vec()))
    }
}
