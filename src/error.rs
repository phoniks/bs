use std::convert;
use std::fmt;
use std::io;
use std::option;
use std::result;

#[derive(Clone, PartialEq)]
pub enum Error {
    Syntax(String),
    InvalidSigil(String),
    InvalidMeta(String),
    InvalidEncoding(String),
    IoError(String),
    Base64EncodingError(String),
    NotUrlSafeBase64(String),
}

pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::Syntax(ref err) |
            Error::InvalidSigil(ref err) |
            Error::InvalidMeta(ref err) |
            Error::InvalidEncoding(ref err) |
            Error::IoError(ref err) |
            Error::Base64EncodingError(ref err) |
            Error::NotUrlSafeBase64(ref err) => err,
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        None
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Syntax(ref err) |
            Error::InvalidSigil(ref err) |
            Error::InvalidMeta(ref err) |
            Error::InvalidEncoding(ref err) |
            Error::IoError(ref err) |
            Error::Base64EncodingError(ref err) |
            Error::NotUrlSafeBase64(ref err) => err.fmt(f),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Syntax(ref err) |
            Error::InvalidSigil(ref err) |
            Error::InvalidMeta(ref err) |
            Error::InvalidEncoding(ref err) |
            Error::IoError(ref err) |
            Error::Base64EncodingError(ref err) |
            Error::NotUrlSafeBase64(ref err) => f.debug_tuple(err).finish()
        }
    }
}

impl convert::From<regex::Error> for Error {
    fn from(error: regex::Error) -> Self {
        match error {
            regex::Error::Syntax(e) => Error::Syntax(e),
            regex::Error::CompiledTooBig(_) => Error::Syntax("compiled too big".to_string()),
            _ => unreachable!(),
        }
    }
}

impl convert::From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        match error {
            base64::DecodeError::InvalidLastSymbol(s, b) |
            base64::DecodeError::InvalidByte(s, b) => {
                let err = format!("invalid base64 byte({}) at ({})", &b.to_string(), &s.to_string());
                Error::Base64EncodingError(err)
            },
            base64::DecodeError::InvalidLength => {
                Error::Base64EncodingError("invalid base64 length".to_string())
            }
        }
    }
}

impl convert::From<option::NoneError> for Error {
    fn from(_: option::NoneError) -> Self {
        Error::Syntax("regex found no matches".to_string())
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        if let Some(inner) = error.into_inner() {
            Error::IoError(format!("{}", inner))
        } else {
            Error::IoError("Unspecified IO error".to_string())
        }
    }
}

impl convert::From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Error::Syntax(format!("{}", error))
    }
}

impl convert::From<()> for Error {
    fn from(_: ()) -> Self {
        Error::Syntax("unknown error".to_string())
    }
}
