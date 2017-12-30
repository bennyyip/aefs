error_chain!{
    foreign_links {
        Io(::std::io::Error);
        Ring(::ring::error::Unspecified);
        OpenSSL(::openssl::error::ErrorStack);
        Break(::rustbreak::BreakError);
        StripPrefix(::std::path::StripPrefixError);
    }
}
