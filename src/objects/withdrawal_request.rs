// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved
use crate::error::Error;
use crate::objects::currency_amount::CurrencyAmount;
use crate::objects::entity::Entity;
use crate::objects::withdrawal_mode::WithdrawalMode;
use crate::objects::withdrawal_request_status::WithdrawalRequestStatus;
use crate::objects::withdrawal_request_to_channel_closing_transactions_connection::WithdrawalRequestToChannelClosingTransactionsConnection;
use crate::objects::withdrawal_request_to_channel_opening_transactions_connection::WithdrawalRequestToChannelOpeningTransactionsConnection;
use crate::requester::requester::Requester;
use crate::types::custom_date_format::custom_date_format;
use crate::types::custom_date_format::custom_date_format_option;
use crate::types::entity_wrapper::EntityWrapper;
use crate::types::get_entity::GetEntity;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct WithdrawalRequest {
    /// The unique identifier of this entity across all Lightspark systems. Should be treated as an opaque string.
    #[serde(rename = "withdrawal_request_id")]
    pub id: String,

    /// The date and time when the entity was first created.
    #[serde(with = "custom_date_format", rename = "withdrawal_request_created_at")]
    pub created_at: DateTime<Utc>,

    /// The date and time when the entity was last updated.
    #[serde(with = "custom_date_format", rename = "withdrawal_request_updated_at")]
    pub updated_at: DateTime<Utc>,

    /// The amount of money that should be withdrawn in this request.
    #[serde(rename = "withdrawal_request_amount")]
    pub amount: CurrencyAmount,

    /// The bitcoin address where the funds should be sent.
    #[serde(rename = "withdrawal_request_bitcoin_address")]
    pub bitcoin_address: String,

    /// The strategy that should be used to withdraw the funds from the account.
    #[serde(rename = "withdrawal_request_withdrawal_mode")]
    pub withdrawal_mode: WithdrawalMode,

    /// The current status of this withdrawal request.
    #[serde(rename = "withdrawal_request_status")]
    pub status: WithdrawalRequestStatus,

    /// The time at which this request was completed.
    #[serde(
        with = "custom_date_format_option",
        rename = "withdrawal_request_completed_at"
    )]
    pub completed_at: Option<DateTime<Utc>>,

    /// The withdrawal transaction that has been generated by this request.
    #[serde(rename = "withdrawal_request_withdrawal")]
    pub withdrawal: Option<EntityWrapper>,
}

impl Entity for WithdrawalRequest {
    /// The unique identifier of this entity across all Lightspark systems. Should be treated as an opaque string.
    fn get_id(&self) -> String {
        return self.id.clone();
    }

    /// The date and time when the entity was first created.
    fn get_created_at(&self) -> DateTime<Utc> {
        return self.created_at;
    }

    /// The date and time when the entity was last updated.
    fn get_updated_at(&self) -> DateTime<Utc> {
        return self.updated_at;
    }

    fn type_name(&self) -> &'static str {
        "WithdrawalRequest"
    }
}

impl GetEntity for WithdrawalRequest {
    fn get_entity_query() -> String {
        return format!(
            "
        query GetEntity($id: ID!) {{
            entity(id: $id) {{
                ... on WithdrawalRequest {{
                    ... WithdrawalRequestFragment
                }}
            }}
        }}

        {}",
            FRAGMENT
        );
    }
}

pub const FRAGMENT: &str = "
fragment WithdrawalRequestFragment on WithdrawalRequest {
    __typename
    withdrawal_request_id: id
    withdrawal_request_created_at: created_at
    withdrawal_request_updated_at: updated_at
    withdrawal_request_amount: amount {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
        currency_amount_preferred_currency_unit: preferred_currency_unit
        currency_amount_preferred_currency_value_rounded: preferred_currency_value_rounded
        currency_amount_preferred_currency_value_approx: preferred_currency_value_approx
    }
    withdrawal_request_bitcoin_address: bitcoin_address
    withdrawal_request_withdrawal_mode: withdrawal_mode
    withdrawal_request_status: status
    withdrawal_request_completed_at: completed_at
    withdrawal_request_withdrawal: withdrawal {
        id
    }
}
";

impl WithdrawalRequest {
    pub async fn get_channel_closing_transactions(
        &self,
        requester: &Requester,
        first: Option<i64>,
    ) -> Result<WithdrawalRequestToChannelClosingTransactionsConnection, Error> {
        let query = "query FetchWithdrawalRequestToChannelClosingTransactionsConnection($entity_id: ID!, $first: Int) {
    entity(id: $entity_id) {
        ... on WithdrawalRequest {
            channel_closing_transactions(, first: $first) {
                __typename
                withdrawal_request_to_channel_closing_transactions_connection_page_info: page_info {
                    __typename
                    page_info_has_next_page: has_next_page
                    page_info_has_previous_page: has_previous_page
                    page_info_start_cursor: start_cursor
                    page_info_end_cursor: end_cursor
                }
                withdrawal_request_to_channel_closing_transactions_connection_count: count
                withdrawal_request_to_channel_closing_transactions_connection_entities: entities {
                    __typename
                    channel_closing_transaction_id: id
                    channel_closing_transaction_created_at: created_at
                    channel_closing_transaction_updated_at: updated_at
                    channel_closing_transaction_status: status
                    channel_closing_transaction_resolved_at: resolved_at
                    channel_closing_transaction_amount: amount {
                        __typename
                        currency_amount_original_value: original_value
                        currency_amount_original_unit: original_unit
                        currency_amount_preferred_currency_unit: preferred_currency_unit
                        currency_amount_preferred_currency_value_rounded: preferred_currency_value_rounded
                        currency_amount_preferred_currency_value_approx: preferred_currency_value_approx
                    }
                    channel_closing_transaction_transaction_hash: transaction_hash
                    channel_closing_transaction_fees: fees {
                        __typename
                        currency_amount_original_value: original_value
                        currency_amount_original_unit: original_unit
                        currency_amount_preferred_currency_unit: preferred_currency_unit
                        currency_amount_preferred_currency_value_rounded: preferred_currency_value_rounded
                        currency_amount_preferred_currency_value_approx: preferred_currency_value_approx
                    }
                    channel_closing_transaction_block_hash: block_hash
                    channel_closing_transaction_block_height: block_height
                    channel_closing_transaction_destination_addresses: destination_addresses
                    channel_closing_transaction_num_confirmations: num_confirmations
                    channel_closing_transaction_channel: channel {
                        id
                    }
                }
            }
        }
    }
}";
        let mut variables: HashMap<&str, Value> = HashMap::new();
        variables.insert("entity_id", self.id.clone().into());
        variables.insert("first", first.into());

        let value = serde_json::to_value(variables).map_err(|err| Error::ConversionError(err))?;
        let result = requester
            .execute_graphql(&query, Some(value))
            .await
            .map_err(|err| Error::ClientError(err))?;
        let json = result["entity"]["channel_closing_transactions"].clone();
        let result = serde_json::from_value(json).map_err(|err| Error::JsonError(err))?;
        Ok(result)
    }

    pub async fn get_channel_opening_transactions(
        &self,
        requester: &Requester,
        first: Option<i64>,
    ) -> Result<WithdrawalRequestToChannelOpeningTransactionsConnection, Error> {
        let query = "query FetchWithdrawalRequestToChannelOpeningTransactionsConnection($entity_id: ID!, $first: Int) {
    entity(id: $entity_id) {
        ... on WithdrawalRequest {
            channel_opening_transactions(, first: $first) {
                __typename
                withdrawal_request_to_channel_opening_transactions_connection_page_info: page_info {
                    __typename
                    page_info_has_next_page: has_next_page
                    page_info_has_previous_page: has_previous_page
                    page_info_start_cursor: start_cursor
                    page_info_end_cursor: end_cursor
                }
                withdrawal_request_to_channel_opening_transactions_connection_count: count
                withdrawal_request_to_channel_opening_transactions_connection_entities: entities {
                    __typename
                    channel_opening_transaction_id: id
                    channel_opening_transaction_created_at: created_at
                    channel_opening_transaction_updated_at: updated_at
                    channel_opening_transaction_status: status
                    channel_opening_transaction_resolved_at: resolved_at
                    channel_opening_transaction_amount: amount {
                        __typename
                        currency_amount_original_value: original_value
                        currency_amount_original_unit: original_unit
                        currency_amount_preferred_currency_unit: preferred_currency_unit
                        currency_amount_preferred_currency_value_rounded: preferred_currency_value_rounded
                        currency_amount_preferred_currency_value_approx: preferred_currency_value_approx
                    }
                    channel_opening_transaction_transaction_hash: transaction_hash
                    channel_opening_transaction_fees: fees {
                        __typename
                        currency_amount_original_value: original_value
                        currency_amount_original_unit: original_unit
                        currency_amount_preferred_currency_unit: preferred_currency_unit
                        currency_amount_preferred_currency_value_rounded: preferred_currency_value_rounded
                        currency_amount_preferred_currency_value_approx: preferred_currency_value_approx
                    }
                    channel_opening_transaction_block_hash: block_hash
                    channel_opening_transaction_block_height: block_height
                    channel_opening_transaction_destination_addresses: destination_addresses
                    channel_opening_transaction_num_confirmations: num_confirmations
                    channel_opening_transaction_channel: channel {
                        id
                    }
                }
            }
        }
    }
}";
        let mut variables: HashMap<&str, Value> = HashMap::new();
        variables.insert("entity_id", self.id.clone().into());
        variables.insert("first", first.into());

        let value = serde_json::to_value(variables).map_err(|err| Error::ConversionError(err))?;
        let result = requester
            .execute_graphql(&query, Some(value))
            .await
            .map_err(|err| Error::ClientError(err))?;
        let json = result["entity"]["channel_opening_transactions"].clone();
        let result = serde_json::from_value(json).map_err(|err| Error::JsonError(err))?;
        Ok(result)
    }
}
