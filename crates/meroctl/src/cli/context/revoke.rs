use calimero_context_config::types::Capability;
use calimero_primitives::alias::Alias;
use calimero_primitives::context::ContextId;
use calimero_primitives::identity::PublicKey;
use calimero_server_primitives::admin::{RevokePermissionRequest, RevokePermissionResponse};
use clap::Parser;
use eyre::{OptionExt, Result as EyreResult};
use reqwest::Client;

use crate::cli::Environment;
use crate::common::{
    fetch_multiaddr, load_config, make_request, multiaddr_to_url, resolve_alias, RequestType,
};

#[derive(Debug, Parser)]
#[command(about = "Revoke permissions from a member in a context")]
pub struct RevokePermissionCommand {
    #[clap(long, short, default_value = "default")]
    pub context: Alias<ContextId>,

    #[clap(long = "as", default_value = "default")]
    pub revoker: Alias<PublicKey>,

    #[clap(help = "The member to revoke permissions from")]
    pub revokee: PublicKey,

    #[clap(help = "The capability to revoke")]
    pub capability: Capability,
}

impl RevokePermissionCommand {
    pub async fn run(self, environment: &Environment) -> EyreResult<()> {
        let config = load_config(&environment.args.home, &environment.args.node_name)?;
        let multiaddr = fetch_multiaddr(&config)?;
        let client = Client::new();

        let context_id = resolve_alias(multiaddr, &config.identity, self.context, None)
            .await?
            .value()
            .cloned()
            .ok_or_eyre("unable to resolve context")?;

        let revoker_id = resolve_alias(multiaddr, &config.identity, self.revoker, Some(context_id))
            .await?
            .value()
            .cloned()
            .ok_or_eyre("unable to resolve revoker identity")?;

        let request = RevokePermissionRequest {
            context_id,
            revoker_id,
            revokee_id: self.revokee,
            capability: self.capability,
        };

        let url = multiaddr_to_url(multiaddr, "admin-api/dev/contexts/revoke-permission")?;

        let _ = make_request::<_, RevokePermissionResponse>(
            environment,
            &client,
            url,
            Some(request),
            &config.identity,
            RequestType::Post,
        )
        .await?;

        println!("Permission revoked successfully");
        Ok(())
    }
}
