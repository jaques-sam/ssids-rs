//! A real bold face. egui ships only Ubuntu Light and its `strong()` merely
//! brightens the colour, too subtle to pick out the connected network.
//! Ubuntu Bold matches the default font and has the same licence
//! (`fonts/UFL.txt`).

use std::sync::Arc;

use eframe::egui::{Context, FontData, FontDefinitions, FontFamily, RichText};

const BOLD: &str = "ubuntu-bold";

/// Registers the bold family; call once before [`bold`] is rendered.
pub fn install(ctx: &Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        BOLD.to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../fonts/Ubuntu-Bold.ttf"
        ))),
    );
    // The regular fonts stay as fallbacks for symbols and emoji.
    let fallbacks = fonts.families[&FontFamily::Proportional].clone();
    let family = std::iter::once(BOLD.to_owned()).chain(fallbacks).collect();
    fonts.families.insert(FontFamily::Name(BOLD.into()), family);
    ctx.set_fonts(fonts);
}

pub fn bold(text: RichText) -> RichText {
    text.family(FontFamily::Name(BOLD.into()))
}
