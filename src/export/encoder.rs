//! csv-core owns only configuration/state, not a private plaintext byte buffer.
use super::{Cause, Stage, StepFailure};
use csv_core::{QuoteStyle, Terminator, WriteResult, Writer, WriterBuilder};
use zeroize::Zeroize;

pub(super) struct SecretBytes<const N: usize> {
    pub bytes: [u8; N],
}
impl<const N: usize> SecretBytes<N> {
    pub fn new() -> Self {
        Self { bytes: [0; N] }
    }
}
impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        super::tests::observe_wiped_buffer(&self.bytes);
    }
}

pub(super) struct Encoder<const N: usize> {
    core: Writer,
    buffer: SecretBytes<N>,
    used: usize,
    failure: Option<StepFailure>,
}
impl<const N: usize> Encoder<N> {
    pub fn new() -> Result<Self, StepFailure> {
        if N < 2 {
            return Err(StepFailure {
                stage: Stage::WriteHeader,
                cause: Cause::InvalidBuffer,
            });
        }
        Ok(Self {
            core: WriterBuilder::new()
                .delimiter(b',')
                .terminator(Terminator::Any(b'\n'))
                .quote(b'"')
                .double_quote(true)
                .quote_style(QuoteStyle::Necessary)
                .comment(None)
                .build(),
            buffer: SecretBytes::new(),
            used: 0,
            failure: None,
        })
    }
    fn drain(
        &mut self,
        emit: &mut impl FnMut(&[u8]) -> Result<(), StepFailure>,
    ) -> Result<(), StepFailure> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.used > 0 {
            let result = emit(&self.buffer.bytes[..self.used]);
            self.buffer.bytes.zeroize();
            self.used = 0;
            if let Err(error) = result {
                self.failure = Some(error);
                return Err(error);
            }
        }
        Ok(())
    }
    fn boundary(
        &mut self,
        kind: u8,
        emit: &mut impl FnMut(&[u8]) -> Result<(), StepFailure>,
    ) -> Result<(), StepFailure> {
        loop {
            let (result, produced) = match kind {
                b',' => self.core.delimiter(&mut self.buffer.bytes[self.used..]),
                b'\n' => self.core.terminator(&mut self.buffer.bytes[self.used..]),
                _ => self.core.finish(&mut self.buffer.bytes[self.used..]),
            };
            self.used += produced;
            if result == WriteResult::InputEmpty {
                return Ok(());
            }
            self.drain(emit)?;
        }
    }
    pub fn record(
        &mut self,
        fields: [&str; 6],
        mut emit: impl FnMut(&[u8]) -> Result<(), StepFailure>,
    ) -> Result<(), StepFailure> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        for (index, field) in fields.into_iter().enumerate() {
            if index != 0 {
                self.boundary(b',', &mut emit)?;
            }
            // First call sees the WHOLE field for the necessary-quote decision.
            let mut remaining = field.as_bytes();
            loop {
                let (result, consumed, produced) = self
                    .core
                    .field(remaining, &mut self.buffer.bytes[self.used..]);
                remaining = &remaining[consumed..];
                self.used += produced;
                if result == WriteResult::InputEmpty {
                    break;
                }
                self.drain(&mut emit)?;
            }
        }
        self.boundary(b'\n', &mut emit)?;
        self.drain(&mut emit)
    }
    pub fn finish(
        &mut self,
        mut emit: impl FnMut(&[u8]) -> Result<(), StepFailure>,
    ) -> Result<(), StepFailure> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.boundary(0, &mut emit)?;
        self.drain(&mut emit)
    }
}
