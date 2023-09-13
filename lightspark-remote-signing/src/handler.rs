use lightspark::{
    objects::{
        id_and_signature::IdAndSignature, remote_signing_sub_event_type::RemoteSigningSubEventType,
        webhook_event_type::WebhookEventType,
    },
    webhooks::WebhookEvent,
};
use log::info;
use serde::Deserialize;
use serde_json::from_value;

use crate::{response::Response, signer::LightsparkSigner, validation::Validation, Error};

pub struct Handler<T>
where
    T: Validation,
{
    signer: LightsparkSigner,
    validator: T,
}

impl<T> Handler<T>
where
    T: Validation,
{
    pub fn new(signer: LightsparkSigner, validator: T) -> Self {
        Self { signer, validator }
    }

    pub fn handle_remote_signing_webhook_msg(
        &self,
        event: &WebhookEvent,
    ) -> Result<Response, Error> {
        if !matches!(event.event_type, WebhookEventType::RemoteSigning) {
            return Err(Error::WebhookEventNotRemoteSigning);
        }

        let data = &event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let sub_type: RemoteSigningSubEventType = from_value(data["sub_event_type"].clone())
            .map_err(|_| Error::WebhookEventDataMissing)?;
        if !self.validator.should_sign(event) {
            self.handle_decline_to_sign_messages(event)
        } else {
            match sub_type {
                RemoteSigningSubEventType::Ecdh => self.handle_ecdh(event),
                RemoteSigningSubEventType::SignInvoice => self.handle_sign_invoice(event),
                RemoteSigningSubEventType::ReleasePaymentPreimage => {
                    self.handle_release_payment_preimage(event)
                }
                RemoteSigningSubEventType::GetPerCommitmentPoint => {
                    self.handle_get_per_commitment_point(event)
                }
                RemoteSigningSubEventType::ReleasePerCommitmentSecret => {
                    self.handle_release_per_commitment_secret(event)
                }
                RemoteSigningSubEventType::DeriveKeyAndSign => {
                    self.handle_derive_key_and_sign(event)
                }
                RemoteSigningSubEventType::RequestInvoicePaymentHash => {
                    self.handle_request_invoice_payment_hash(event)
                }
            }
        }
    }

    fn handle_request_invoice_payment_hash(&self, event: &WebhookEvent) -> Result<Response, Error> {
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let invoice_id = data["invoice_id"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;
        let nonce = self.signer.generate_preimage_nonce();
        let nonce_str = hex::encode(&nonce);

        let payment_hash = self
            .signer
            .generate_preimage_hash(nonce)
            .map_err(Error::SignerError)?;
        let payment_hash_str = hex::encode(payment_hash);
        Ok(Response::set_invoice_payment_hash_response(
            invoice_id,
            &payment_hash_str,
            &nonce_str,
        ))
    }

    fn handle_decline_to_sign_messages(&self, event: &WebhookEvent) -> Result<Response, Error> {
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;

        let signing_jobs: Vec<SigningJob> = serde_json::from_value(data["signing_jobs"].clone())
            .map_err(|_| Error::WebhookEventDataMissing)?;

        let payload_ids: Vec<String> = signing_jobs.iter().map(|job| job.id.clone()).collect();
        Ok(Response::decline_to_sign_message_response(&payload_ids))
    }

    fn handle_ecdh(&self, event: &WebhookEvent) -> Result<Response, Error> {
        info!("Handling ECDH webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let node_id = &event.entity_id;
        let public_key = data["public_key"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;
        let public_key_bytes = hex::decode(public_key).map_err(Error::PublicKeyDecodeError)?;
        let ss = self
            .signer
            .ecdh(public_key_bytes.to_vec())
            .map_err(Error::SignerError)?;
        let ss_str = hex::encode(ss);
        Ok(Response::ecdh_response(node_id, &ss_str))
    }

    fn handle_sign_invoice(&self, event: &WebhookEvent) -> Result<Response, Error> {
        info!("Handling sign invoice webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let invoice_id = data["invoice_id"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;
        let invoice_hash = data["payreq_hash"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;
        let invoice_hash_bytes = hex::decode(invoice_hash).map_err(|_| Error::HexEncodingError)?;
        let signature = self
            .signer
            .sign_invoice_hash(invoice_hash_bytes)
            .map_err(Error::SignerError)?;
        Ok(Response::sign_invoice_response(
            invoice_id,
            hex::encode(signature.get_signature()).as_str(),
            signature.get_recovery_id(),
        ))
    }

    fn handle_release_payment_preimage(&self, event: &WebhookEvent) -> Result<Response, Error> {
        info!("Handling release payment preimage webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let nonce = data["preimage_nonce"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;
        let invoice_id = data["invoice_id"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;

        let nonce_bytes = hex::decode(nonce).map_err(|_| Error::HexEncodingError)?;
        let preimage = self
            .signer
            .generate_preimage(nonce_bytes)
            .map_err(Error::SignerError)?;

        Ok(Response::release_payment_preimage_response(
            invoice_id,
            hex::encode(preimage).as_str(),
        ))
    }

    fn handle_get_per_commitment_point(&self, event: &WebhookEvent) -> Result<Response, Error> {
        info!("Handling get per commitment point webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let per_commitment_point_idx = data["per_commitment_point_idx"]
            .as_u64()
            .ok_or(Error::WebhookEventDataMissing)?;

        let derivation_path = data["derivation_path"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;

        let channel_id = &event.entity_id;

        let per_commitment_point = self
            .signer
            .get_per_commitment_point(derivation_path.to_string(), per_commitment_point_idx)
            .map_err(Error::SignerError)?;

        let commitment_point_str = hex::encode(per_commitment_point);
        Ok(Response::get_channel_per_commitment_response(
            channel_id,
            commitment_point_str.as_str(),
            per_commitment_point_idx,
        ))
    }

    fn handle_release_per_commitment_secret(
        &self,
        event: &WebhookEvent,
    ) -> Result<Response, Error> {
        info!("Handling release per commitment secret webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;
        let per_commitment_point_idx = data["per_commitment_point_idx"]
            .as_u64()
            .ok_or(Error::WebhookEventDataMissing)?;

        let derivation_path = data["derivation_path"]
            .as_str()
            .ok_or(Error::WebhookEventDataMissing)?;

        let channel_id = &event.entity_id;
        let commitment_secret = self
            .signer
            .release_per_commitment_secret(derivation_path.to_string(), per_commitment_point_idx)
            .map_err(Error::SignerError)?;

        let commitment_secret_str = hex::encode(commitment_secret);

        Ok(Response::release_channel_per_commitment_secret_response(
            channel_id,
            &commitment_secret_str,
        ))
    }

    fn handle_derive_key_and_sign(&self, event: &WebhookEvent) -> Result<Response, Error> {
        info!("Handling derive key and sign webhook event");
        let data = event.data.as_ref().ok_or(Error::WebhookEventDataMissing)?;

        let signing_jobs: Vec<SigningJob> = serde_json::from_value(data["signing_jobs"].clone())
            .map_err(|_| Error::WebhookEventDataMissing)?;

        let mut signatures: Vec<IdAndSignature> = vec![];
        for signing_job in signing_jobs {
            let signature = self
                .signer
                .derive_key_and_sign(
                    hex::decode(signing_job.message).map_err(|_| Error::HexEncodingError)?,
                    signing_job.derivation_path,
                    signing_job.is_raw,
                    signing_job
                        .add_tweak
                        .map(|tweak| hex::decode(tweak).map_err(|_| Error::HexEncodingError))
                        .transpose()?,
                    signing_job
                        .mul_tweak
                        .map(|tweak| hex::decode(tweak).map_err(|_| Error::HexEncodingError))
                        .transpose()?,
                )
                .map_err(Error::SignerError)?;

            signatures.push(IdAndSignature {
                id: signing_job.id,
                signature: hex::encode(signature),
            });
        }
        Ok(Response::sign_messages_response(signatures))
    }
}

#[derive(Clone, Deserialize, Debug)]
struct SigningJob {
    id: String,
    derivation_path: String,
    message: String,
    add_tweak: Option<String>,
    mul_tweak: Option<String>,
    is_raw: bool,
}

#[cfg(test)]
mod tests {
    use lightspark::webhooks::WebhookEvent;

    use crate::signer::{LightsparkSigner, Seed};

    #[test]
    fn test_handle_remote_signing_webhook_msg_ecdh() {
        let data = "{\"event_type\": \"REMOTE_SIGNING\", \"event_id\": \"1615c8be5aa44e429eba700db2ed8ca5\", \"timestamp\": \"2023-05-17T23:56:47.874449+00:00\", \"entity_id\": \"lightning_node:01882c25-157a-f96b-0000-362d42b64397\", \"data\": {\"sub_event_type\": \"ECDH\", \"public_key\": \"027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c\"}}";
        let hexdigest = "17db38526ce47682f4052e3182766fe2f23810ac538e32d5f20bbe1deb2e3519";
        let webhook_secret = "3gZ5oQQUASYmqQNuEk0KambNMVkOADDItIJjzUlAWjX";

        let result = WebhookEvent::verify_and_parse(
            data.as_bytes(),
            hexdigest.to_string(),
            webhook_secret.to_string(),
        )
        .expect("Success case");

        let seed = Seed::new("test".as_bytes().to_vec());
        let signer = LightsparkSigner::new(&seed, crate::signer::Network::Bitcoin).unwrap();
        let validator = crate::validation::PositiveValidator;
        let handler = super::Handler::new(signer, validator);
        let response = handler
            .handle_remote_signing_webhook_msg(&result)
            .expect("Success case");

        let ss = response.variables["shared_secret"].as_str().unwrap();
        assert_eq!(
            ss,
            "930d00c9247dd9415b26855a5faafef14705460dfcc4c43fba2f2d899424d31b"
        );
    }
}