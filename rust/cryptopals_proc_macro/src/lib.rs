//! Collection of procedural macros that can be used with the `cryptopals` crate
//!
//! ## Examples
//!
//! In this example, both values are exactly equal, since the transformation
//! happens at compile-time.
//!
//! ```
//! # use cryptopals_proc_macro::str_to_16_bytes;
//! #
//! let value_1 = str_to_16_bytes!("YELLOW SUBMARINE");
//! let value_2 = [
//!     89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69,
//! ];
//!
//! assert_eq!(value_1, value_2);
//! ```
//!
//! In this example, there will be a compiler error since the string is not
//! exactly 16 bytes.
//!
//! ```compile_fail
//! # use cryptopals_proc_macro::str_to_16_bytes;
//! #
//! let value = str_to_16_bytes!("cryptopals");
//! ```
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Error, LitStr};

/// A procedural macro which transforms the input string to an `u8` array of
/// length 16.
#[proc_macro]
pub fn str_to_16_bytes(input: TokenStream) -> TokenStream {
    // Extract the string from the input token stream
    let input = parse_macro_input!(input as LitStr);
    let string = input.value();

    // Validate the length of the string
    if string.len() != 16 {
        let error = Error::new(input.span(), "The provided string is not 16 bytes long.");
        return TokenStream::from(error.to_compile_error());
    }

    // Convert the array into tokens
    let tokens = string.as_bytes().iter().map(|&b| quote!(#b));

    // Generate the output token stream
    let expanded = quote! {
        [#(#tokens),*]
    };

    TokenStream::from(expanded)
}
