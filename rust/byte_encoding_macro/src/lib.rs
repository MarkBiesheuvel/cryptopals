use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Error, LitStr};

use byte_encoding::decode_hexadecimal;

#[proc_macro]
pub fn hex(input: TokenStream) -> TokenStream {
    // Parse the input as a literal string
    let input = parse_macro_input!(input as LitStr);

    // Decode as hexadecimal
    let bytes = match decode_hexadecimal(input.value()) {
        Ok(bytes) => bytes,
        Err(_error) => {
            return Error::new_spanned(input, "TODO: impl Error for EncodingError")
                .to_compile_error()
                .into();
        }
    };

    // Generate code
    let output = quote!(
        {
            [ #(#bytes),* ]
        }
    );

    output.into()
}
