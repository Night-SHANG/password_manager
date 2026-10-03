//! Owned off-thread preparation. Only a claimed exact lease enters publication.
//! Standalone synchronous callers use the same private core without fabricating
//! coordinator authority. A lease never replaces the filesystem source checks.
use super::*;
use crate::operations::authority::CommitLease;
use crate::operations::{OperationId, PreparedBinding, SessionBinding};
use crate::platform::file_transaction::Identity;

/// New-file errors cannot borrow an existing-target transaction's proof. Once
/// publication is attempted, retain the destination and report the observation.
pub(crate) enum NewFileOutcome<T> {
    BeforePublication(AppError),
    PublicationAttempted {
        error: AppError,
        recovery: recovery::RecoveryInfo,
    },
    Verified(T),
}
impl<T> NewFileOutcome<T> {
    pub(crate) fn into_result(self) -> Result<T> {
        match self {
            Self::BeforePublication(error) => Err(error),
            Self::PublicationAttempted { error, recovery } => {
                Err(AppError::Persist(Box::new(transaction::PersistFailure {
                    disposition: transaction::Disposition::RecoveryRequired,
                    stage: recovery.stage.clone(),
                    primary: error.to_string(),
                    secondary: Vec::new(),
                    recovery,
                })))
            }
            Self::Verified(value) => Ok(value),
        }
    }

    // Keep the public synchronous APIs' historical typed errors as well as their
    // signatures. Coordinated callers receive the stronger publication boundary.
    fn into_standalone_result(self) -> Result<T> {
        match self {
            Self::BeforePublication(error) | Self::PublicationAttempted { error, .. } => Err(error),
            Self::Verified(value) => Ok(value),
        }
    }
}

struct PreparedAuthority {
    id: Uuid,
    session: Option<SessionBinding>,
    binding: Option<PreparedBinding>,
}
impl PreparedAuthority {
    fn new(session: Option<SessionBinding>) -> Self {
        Self {
            id: Uuid::new_v4(),
            session,
            binding: None,
        }
    }
    fn associate_operation(&mut self, operation: OperationId) -> PreparedBinding {
        // Association is immutable. A different later operation cannot rebind
        // this same prepared owner or revive an already-issued authority.
        *self.binding.get_or_insert(PreparedBinding {
            prepared_id: self.id,
            operation,
            session: self.session,
        })
    }
    fn authorize(&self, lease: &CommitLease) -> Result<()> {
        if self
            .binding
            .is_some_and(|binding| lease.authorizes(binding))
        {
            Ok(())
        } else {
            Err(AppError::Input(
                "prepared operation authority mismatch".into(),
            ))
        }
    }
    fn check_session(&self, session: &VaultSession) -> Result<()> {
        if self.session == Some(session.operation_binding()) {
            Ok(())
        } else {
            Err(AppError::Input("prepared session no longer matches".into()))
        }
    }
}
macro_rules! prepared_binding {
    ($owner:ident) => {
        impl $owner {
            pub(crate) fn binding(&self) -> Option<PreparedBinding> {
                self.authority.binding
            }
            pub(crate) fn associate_operation(
                &mut self,
                operation: OperationId,
            ) -> PreparedBinding {
                match self.binding() {
                    Some(binding) => binding,
                    None => self.authority.associate_operation(operation),
                }
            }
        }
    };
}

pub(crate) struct PreparedCreate {
    authority: PreparedAuthority,
    destination: PathBuf,
    header: PublicHeader,
    body: VaultBody,
    keys: VaultKeys,
    bytes: Zeroizing<Vec<u8>>,
}
prepared_binding!(PreparedCreate);

pub(crate) fn prepare_create(
    path: impl Into<PathBuf>,
    master_password: &str,
) -> Result<PreparedCreate> {
    let destination = path.into();
    if destination.exists() {
        return Err(AppError::AlreadyExists);
    }
    if master_password.is_empty() {
        return Err(AppError::Input("主密码不能为空".into()));
    }
    let kdf_params = KdfConfig::default().validate()?;
    let salt = random_array::<SALT_LEN>()?;
    let wrap_nonce = random_array::<NONCE_LEN>()?;
    let vault_key = Zeroizing::new(random_array::<32>()?);
    let vault_id = Uuid::new_v4();
    let mut kek = Zeroizing::new(derive_kek(master_password, &salt, kdf_params)?);
    let wrapped_vault_key = seal(
        &kek,
        &wrap_nonce,
        &keywrap_aad(vault_id, kdf_params, &salt),
        &vault_key[..],
    )?;
    kek.zeroize();
    let header = PublicHeader {
        magic: MAGIC.into(),
        format_version: FORMAT_VERSION,
        vault_id,
        revision: 1,
        kdf: "argon2id".into(),
        kdf_params,
        kdf_salt: b64(&salt),
        wrap_nonce: b64(&wrap_nonce),
        wrapped_vault_key: b64(&wrapped_vault_key),
    };
    let keys = VaultKeys::from_vault_key(*vault_key)?;
    let body = VaultBody::default();
    let bytes = Zeroizing::new(encode_file(&header, &body, &keys)?);
    verify_encoded_bytes(&bytes, &header, &body, &keys)?;
    Ok(PreparedCreate {
        authority: PreparedAuthority::new(None),
        destination,
        header,
        body,
        keys,
        bytes,
    })
}
impl PreparedCreate {
    pub(crate) fn commit(self, lease: &CommitLease) -> Result<VaultSession> {
        self.commit_outcome(lease).into_result()
    }
    pub(crate) fn commit_outcome(self, lease: &CommitLease) -> NewFileOutcome<VaultSession> {
        if let Err(error) = self.authority.authorize(lease) {
            return NewFileOutcome::BeforePublication(error);
        }
        self.commit_core()
    }
    pub(super) fn commit_standalone(self) -> Result<VaultSession> {
        self.commit_core().into_standalone_result()
    }
    fn commit_core(self) -> NewFileOutcome<VaultSession> {
        let outcome = publish_new_file(&self.destination, &self.bytes, |bytes| {
            verify_encoded_bytes(bytes, &self.header, &self.body, &self.keys)
        });
        match outcome {
            NewFileOutcome::Verified(receipt) => NewFileOutcome::Verified(VaultSession {
                instance_id: Uuid::new_v4(),
                import_epoch: Uuid::new_v4(),
                path: receipt.path,
                header: self.header,
                body: self.body,
                keys: self.keys,
                source_hash: receipt.hash,
                source_identity: receipt.identity,
                write_invalid: false,
                maintenance_warning: None,
            }),
            NewFileOutcome::BeforePublication(error) => NewFileOutcome::BeforePublication(error),
            NewFileOutcome::PublicationAttempted { error, recovery } => {
                NewFileOutcome::PublicationAttempted { error, recovery }
            }
        }
    }
}

pub(crate) struct PreparedSave {
    authority: PreparedAuthority,
    body: VaultBody,
    next_header: PublicHeader,
    bytes: Zeroizing<Vec<u8>>,
}
prepared_binding!(PreparedSave);
pub(super) fn prepare_save(session: &VaultSession) -> Result<PreparedSave> {
    session.ensure_maintenance_ready()?;
    if session.write_invalid {
        return Err(AppError::ExternalChange);
    }
    let mut next_header = session.header.clone();
    next_header.revision = next_header
        .revision
        .checked_add(1)
        .ok_or(AppError::InvalidVault("revision overflow"))?;
    let body = session.body.clone();
    let bytes = Zeroizing::new(encode_file(&next_header, &body, &session.keys)?);
    ensure_save_candidate_size(session, &bytes)?;
    verify_encoded_bytes(&bytes, &next_header, &body, &session.keys)?;
    Ok(PreparedSave {
        authority: PreparedAuthority::new(Some(session.operation_binding())),
        body,
        next_header,
        bytes,
    })
}
// Preserve the transaction's size-first rejection before preparation allocates
// a decoded/authenticated candidate. Reuse its read-only failure observation,
// retaining the exact original candidate-size disposition and metadata without
// entering any commit/namespace operation from a preparer.
fn ensure_save_candidate_size(session: &VaultSession, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 <= MAX_VAULT_BYTES {
        return Ok(());
    }
    let mut error = transaction::current_source_failure(
        transaction::SourceExpectation {
            target: &session.path,
            hash: session.source_hash,
            identity: session.source_identity,
        },
        AppError::InvalidVault("candidate exceeds size limit"),
    );
    if let AppError::Persist(failure) = &mut error {
        failure.disposition = transaction::Disposition::Unchanged;
        failure.stage = "candidate size".into();
        failure.recovery.stage = "candidate size".into();
    }
    Err(error)
}

impl PreparedSave {
    pub(crate) fn commit(self, lease: &CommitLease, session: &mut VaultSession) -> Result<()> {
        self.authority.authorize(lease)?;
        self.commit_core(session)
    }
    pub(super) fn commit_core(self, session: &mut VaultSession) -> Result<()> {
        self.authority.check_session(session)?;
        if self.body != session.body {
            return Err(AppError::Input("prepared body no longer matches".into()));
        }
        session.ensure_maintenance_ready()?;
        if session.write_invalid {
            return Err(AppError::ExternalChange);
        }
        let result = transaction::commit(
            transaction::SourceExpectation {
                target: &session.path,
                hash: session.source_hash,
                identity: session.source_identity,
            },
            &self.bytes,
            |old| session.verify_baseline(old),
            |new| verify_encoded_bytes(new, &self.next_header, &self.body, &session.keys),
        );
        match result {
            Ok(receipt) => {
                session.header = self.next_header;
                session.source_hash = receipt.hash;
                session.source_identity = receipt.identity;
                session.maintenance_warning = receipt.warning;
                Ok(())
            }
            Err(error) => {
                invalidate_on_failure(session, &error);
                Err(error)
            }
        }
    }
}

pub(crate) struct PreparedRestore {
    authority: PreparedAuthority,
    destination_body: VaultBody,
    bytes: Zeroizing<Vec<u8>>,
    candidate: VaultSession,
}
prepared_binding!(PreparedRestore);
pub(crate) fn prepare_restore_current(
    session: &VaultSession,
    source: &Path,
    master_password: &str,
) -> Result<PreparedRestore> {
    session.ensure_maintenance_ready()?;
    if session.write_invalid {
        return Err(AppError::ExternalChange);
    }
    if same_path(source, &session.path) {
        return Err(AppError::Input("恢复源与目标不能是同一个文件".into()));
    }
    let (bytes, identity) = bounded::read_identified(source, MAX_VAULT_BYTES)?;
    let bytes = Zeroizing::new(bytes);
    let candidate =
        VaultSession::from_captured(source.to_path_buf(), master_password, &bytes, identity)?;
    Ok(PreparedRestore {
        authority: PreparedAuthority::new(Some(session.operation_binding())),
        destination_body: session.body.clone(),
        bytes,
        candidate,
    })
}
impl PreparedRestore {
    pub(crate) fn commit(
        self,
        lease: &CommitLease,
        session: &mut VaultSession,
    ) -> Result<VaultSession> {
        self.authority.authorize(lease)?;
        self.commit_core(session)
    }
    pub(super) fn commit_core(mut self, session: &mut VaultSession) -> Result<VaultSession> {
        self.authority.check_session(session)?;
        if self.destination_body != session.body {
            return Err(AppError::Input("prepared body no longer matches".into()));
        }
        session.ensure_maintenance_ready()?;
        if session.write_invalid {
            return Err(AppError::ExternalChange);
        }
        let result = transaction::commit(
            transaction::SourceExpectation {
                target: &session.path,
                hash: session.source_hash,
                identity: session.source_identity,
            },
            &self.bytes,
            |old| session.verify_baseline(old),
            |new| {
                verify_encoded_bytes(
                    new,
                    &self.candidate.header,
                    &self.candidate.body,
                    &self.candidate.keys,
                )
            },
        );
        match result {
            Ok(receipt) => {
                self.candidate.path = session.path.clone();
                self.candidate.source_hash = receipt.hash;
                self.candidate.source_identity = receipt.identity;
                self.candidate.maintenance_warning = receipt.warning;
                session.write_invalid = true;
                session.consume_import_preview();
                Ok(self.candidate)
            }
            Err(error) => {
                invalidate_on_failure(session, &error);
                Err(error)
            }
        }
    }
}

pub(crate) struct PreparedBackup {
    authority: PreparedAuthority,
    destination: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
    hash: [u8; 32],
    captured_body: VaultBody,
}
prepared_binding!(PreparedBackup);
pub(crate) fn prepare_backup(session: &VaultSession, destination: &Path) -> Result<PreparedBackup> {
    if same_path(&session.path, destination) {
        return Err(AppError::Input("备份目标不能与当前保险库相同".into()));
    }
    if destination.exists() {
        return Err(AppError::AlreadyExists);
    }
    let (bytes, identity) = bounded::read_identified(&session.path, MAX_VAULT_BYTES)?;
    let bytes = Zeroizing::new(bytes);
    if identity != session.source_identity || security::sha256(&bytes) != session.source_hash {
        return Err(AppError::ExternalChange);
    }
    // Authenticate the saved disk body. Unsaved in-memory edits need not equal
    // a backup of the last saved snapshot, and are never silently published.
    let captured_body = session.authenticated_baseline(&bytes)?;
    verify_encoded_bytes(&bytes, &session.header, &captured_body, &session.keys)?;
    Ok(PreparedBackup {
        authority: PreparedAuthority::new(Some(session.operation_binding())),
        destination: destination.to_path_buf(),
        bytes,
        hash: session.source_hash,
        captured_body,
    })
}
impl PreparedBackup {
    pub(crate) fn commit(self, lease: &CommitLease, session: &VaultSession) -> Result<()> {
        self.commit_outcome(lease, session).into_result()
    }
    pub(crate) fn commit_outcome(
        self,
        lease: &CommitLease,
        session: &VaultSession,
    ) -> NewFileOutcome<()> {
        if let Err(error) = self
            .authority
            .authorize(lease)
            .and_then(|()| self.authority.check_session(session))
        {
            return NewFileOutcome::BeforePublication(error);
        }
        self.commit_core(session)
    }
    pub(super) fn commit_standalone(self, session: &VaultSession) -> Result<()> {
        self.commit_core(session).into_standalone_result()
    }
    fn commit_core(self, session: &VaultSession) -> NewFileOutcome<()> {
        if let Err(error) = self.authority.check_session(session) {
            return NewFileOutcome::BeforePublication(error);
        }
        map_verified(
            publish_new_file(&self.destination, &self.bytes, |bytes| {
                if security::sha256(bytes) != self.hash {
                    return Err(AppError::InvalidVault(
                        "encrypted backup verification failed",
                    ));
                }
                verify_encoded_bytes(bytes, &session.header, &self.captured_body, &session.keys)
            }),
            |_| (),
        )
    }
}

pub(crate) struct PreparedRestoreNew {
    authority: PreparedAuthority,
    destination: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
    candidate: VaultSession,
}
prepared_binding!(PreparedRestoreNew);
pub(crate) fn prepare_restore_new(
    source: &Path,
    destination: &Path,
    master_password: &str,
) -> Result<PreparedRestoreNew> {
    if same_path(source, destination) {
        return Err(AppError::Input("恢复源与目标不能是同一个文件".into()));
    }
    if destination.exists() {
        return Err(AppError::AlreadyExists);
    }
    let (bytes, identity) = bounded::read_identified(source, MAX_VAULT_BYTES)?;
    let bytes = Zeroizing::new(bytes);
    let candidate =
        VaultSession::from_captured(source.to_path_buf(), master_password, &bytes, identity)?;
    Ok(PreparedRestoreNew {
        authority: PreparedAuthority::new(None),
        destination: destination.to_path_buf(),
        bytes,
        candidate,
    })
}
impl PreparedRestoreNew {
    pub(crate) fn commit(self, lease: &CommitLease) -> Result<()> {
        self.commit_outcome(lease).into_result()
    }
    pub(crate) fn commit_outcome(self, lease: &CommitLease) -> NewFileOutcome<()> {
        if let Err(error) = self.authority.authorize(lease) {
            return NewFileOutcome::BeforePublication(error);
        }
        self.commit_core()
    }
    pub(super) fn commit_standalone(self) -> Result<()> {
        self.commit_core().into_standalone_result()
    }
    fn commit_core(self) -> NewFileOutcome<()> {
        map_verified(
            publish_new_file(&self.destination, &self.bytes, |bytes| {
                if bytes != self.bytes.as_slice() {
                    return Err(AppError::InvalidVault(
                        "restored encrypted backup failed verification",
                    ));
                }
                verify_encoded_bytes(
                    bytes,
                    &self.candidate.header,
                    &self.candidate.body,
                    &self.candidate.keys,
                )
            }),
            |_| (),
        )
    }
}

fn invalidate_on_failure(session: &mut VaultSession, error: &AppError) {
    if error.invalidates_session() {
        session.write_invalid = true;
        session.consume_import_preview();
    }
}
fn map_verified<T, U>(outcome: NewFileOutcome<T>, map: impl FnOnce(T) -> U) -> NewFileOutcome<U> {
    match outcome {
        NewFileOutcome::BeforePublication(error) => NewFileOutcome::BeforePublication(error),
        NewFileOutcome::PublicationAttempted { error, recovery } => {
            NewFileOutcome::PublicationAttempted { error, recovery }
        }
        NewFileOutcome::Verified(value) => NewFileOutcome::Verified(map(value)),
    }
}
struct NewFileReceipt {
    path: PathBuf,
    hash: [u8; 32],
    identity: Identity,
}

fn publish_new_file(
    destination: &Path,
    bytes: &[u8],
    verify: impl Fn(&[u8]) -> Result<()>,
) -> NewFileOutcome<NewFileReceipt> {
    // The coordinated caller has already checked its lease before the first
    // parent/temp mutation. No cancellation path exists after this boundary.
    if destination.exists() {
        return NewFileOutcome::BeforePublication(AppError::AlreadyExists);
    }
    let temp = tempfile::TempPath::from_path(temp_path_for(destination));
    if let Err(error) = write_temp_file(&temp, bytes) {
        return NewFileOutcome::BeforePublication(error);
    }
    #[cfg(test)]
    if let Err(error) = transaction::test_hook(transaction::Point::BeforePublish) {
        return NewFileOutcome::BeforePublication(error);
    }
    if let Err(error) = platform::atomic_create_new(destination, temp) {
        return if matches!(error, AppError::AlreadyExists) {
            NewFileOutcome::BeforePublication(error)
        } else {
            attempted_failure(destination, bytes, "new-file publication", error)
        };
    }
    #[cfg(test)]
    tests::run_after_publish_hook();
    #[cfg(test)]
    if let Err(error) = transaction::test_hook(transaction::Point::AfterPublish) {
        return attempted_failure(destination, bytes, "after new-file publication", error);
    }
    #[cfg(test)]
    if let Err(error) = transaction::test_hook(transaction::Point::BeforeVerify) {
        return attempted_failure(destination, bytes, "new-file verification", error);
    }
    let result = (|| {
        let (persisted, identity) = bounded::read_identified(destination, MAX_VAULT_BYTES)?;
        let persisted = Zeroizing::new(persisted);
        verify(&persisted)?;
        if persisted.as_slice() != bytes {
            return Err(AppError::InvalidVault(
                "published file differs from intended candidate",
            ));
        }
        Ok(NewFileReceipt {
            path: recovery::normalized_destination_path(destination)?,
            hash: security::sha256(&persisted),
            identity,
        })
    })();
    match result {
        Ok(receipt) => NewFileOutcome::Verified(receipt),
        Err(error) => attempted_failure(destination, bytes, "new-file verification", error),
    }
}
fn attempted_failure<T>(
    destination: &Path,
    candidate: &[u8],
    stage: &str,
    error: AppError,
) -> NewFileOutcome<T> {
    let current = match bounded::read(destination, MAX_VAULT_BYTES) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.as_slice() == candidate {
                recovery::CurrentObservation::ExpectedCandidate
            } else {
                recovery::CurrentObservation::Other
            }
        }
        Err(AppError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            recovery::CurrentObservation::Missing
        }
        Err(_) => recovery::CurrentObservation::Unreadable,
    };
    NewFileOutcome::PublicationAttempted {
        error,
        recovery: recovery::RecoveryInfo {
            destination: destination.to_path_buf(), stage: stage.into(), current, artifacts: Vec::new(),
            detail: "新文件发布已经尝试，完整结果未确认。请保留目标，验证后恢复到另一个新文件。未执行删除或自动回滚。".into(),
        },
    }
}
