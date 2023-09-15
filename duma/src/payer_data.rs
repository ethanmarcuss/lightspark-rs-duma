// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayerDataOptions {
    pub name_required: bool,
    pub email_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PayerDataOption {
    mandatory: bool,
}

impl Serialize for PayerDataOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PayerDataOptions", 4)?;
        state.serialize_field("identifier", &PayerDataOption { mandatory: true })?;
        state.serialize_field(
            "name",
            &PayerDataOption {
                mandatory: self.name_required,
            },
        )?;
        state.serialize_field(
            "email",
            &PayerDataOption {
                mandatory: self.email_required,
            },
        )?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PayerDataOptions {
    fn deserialize<D>(deserializer: D) -> Result<PayerDataOptions, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};

        struct PayerDataOptionsVisitor;

        impl<'de> Visitor<'de> for PayerDataOptionsVisitor {
            type Value = PayerDataOptions;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct PayerDataOptions")
            }

            fn visit_map<A>(self, mut map: A) -> Result<PayerDataOptions, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut name_required = false;
                let mut email_required = false;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "name" => {
                            let option: PayerDataOption = map.next_value()?;
                            name_required = option.mandatory;
                        }
                        "email" => {
                            let option: PayerDataOption = map.next_value()?;
                            email_required = option.mandatory;
                        } _ => {
                            let _: PayerDataOption = map.next_value()?;
                        }
                    }
                }

                Ok(PayerDataOptions {
                    name_required,
                    email_required,
                })
            }
        }

        deserializer.deserialize_map(PayerDataOptionsVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayerData {
    pub name: Option<String>,
    pub email: Option<String>,
    pub identifier: String,
}    /// utxos is the list of UTXOs of the sender's channels that might be used to fund the payment.
    pub utxos: Vec<String>,

    /// node_pubkey is the public key of the sender's node if known.
    #[serde(rename = "nodePubkey")]
    pub node_pubkey: Option<String>,

    /// encrypted_travel_rule_info is the travel rule information of the sender. This is encrypted
    /// with the receiver's public encryption key.
    #[serde(rename = "encryptedTravelRuleInfo")]
    pub encrypted_travel_rule_info: Option<String>,

    // signature is the hex-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
    pub signature: String,

    #[serde(rename = "signatureNonce")]
    pub signature_nonce: String,

    #[serde(rename = "signatureTimestamp")]
    pub signature_timestamp: i64,

    /// UtxoCallback is the URL that the receiver will call to send UTXOs of the channel that the
    /// receiver used to receive the payment once it completes.
    #[serde(rename = "utxoCallback")]
    pub utxo_callback: String,
}
