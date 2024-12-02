mod atproto;
mod context;
mod coordinator;
mod crypto;
mod did;
mod domain;
mod errors;
mod ui;

use errors::SetupResult;

fn main() -> SetupResult<()> {
    smol::block_on(async {
        let mut setup_ui = ui::SetupUI::new()?;
        setup_ui.run().await
    })
}
