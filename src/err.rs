use std::error;
use std::fmt::{Display, Formatter};

/// represents the kind of error that occurred.
#[derive(Debug, Clone)]
pub enum ErrorKind {
    /// An error that occurs during patching.
    PatchingError,
    /// An error that occurs when trying to parse a patch file.
    ParsingError,
}

/// Represents an error specific to patching roms.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    description: Option<String>,
    source: Option<Box<dyn error::Error>>,
}

impl Error {
    /// Create a new Error with a given `kind`.
    pub fn new(kind: ErrorKind) -> Error {
        return Error {
            kind,
            description: None,
            source: None,
        };
    }

    /// Modifies the error with a given `description`.
    pub fn with_description(self, description: String) -> Error {
        return Error {
            kind: self.kind,
            description: Some(description),
            source: self.source,
        };
    }

    /// Modifies the error with a given `source`.
    pub fn with_source(self, source: Box<dyn error::Error>) -> Error {
        return Error {
            kind: self.kind,
            description: self.description,
            source: Some(source),
        };
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(description) = &self.description {
            write!(f, "{:?}: {}", self.kind, description)
        } else {
            write!(f, "{:?}", self.kind)
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        if let Some(v) = &self.source {
            Some(v.as_ref())
        } else {
            None
        }
    }
}