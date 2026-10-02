# Verified saves and encrypted recovery copies

Existing-file save, import commit and confirmed overwrite restore share one
synchronous verified transaction. New-file create, backup export and recovery to
a new file still use no-clobber publication.

## What a successful save means

The app holds a stable same-parent sidecar OS lock; it never removes that lock
file. It verifies the saved source digest and file identity, stages an independent
encrypted preimage, candidate and publication copy with exclusive creation,
syncs and reads them back, then rechecks the live source. An encoded candidate
larger than 64 MiB is rejected before hashing/authentication or namespace mutation,
so a predictable size rejection does not create recovery debris. Linux publishes by
`renameat_with(EXCHANGE)` using opened directories. Windows uses existing-target
`ReplaceFileW` with a unique absent backup path and supported flags. There is no
missing-target create or clobbering-rename fallback.

Before the publish attempt, cleanup guards become inert. The actual displaced
file and newly opened live candidate are verified, including a fresh checkpoint
after supported synchronization. Only the verified receipt advances the session.
An external conflict invalidates the write session. Uncertain publication,
displaced-file mismatch or verification/sync failure locks the UI and preserves
recovery evidence. There is **no automatic overwrite rollback or repair**.

The lock coordinates cooperating app writers. Hash/file-ID checks are not a
filesystem compare-and-swap and do not exclude arbitrary writers. These are
verified checkpoints, not a promise against a change after the checkpoint.
Supported scope is local same-volume regular files, a stable physical parent,
and a nonmalicious managed namespace. Final links/reparse points, hardlink aliases
and Windows alternate streams are rejected. Linux currently allowlists ext,
XFS, Btrfs, tmpfs and overlay filesystems. Other/network filesystems fail closed.
Windows limits transactions to local fixed/RAM volumes; real NTFS sharing/ACL
behavior remains part of Windows execution testing.

## Retention and maintenance

Private same-parent `.pmvault-<destination-key>.txn-<uuid>` directories contain
fixed encrypted roles and bounded nonsecret receipts. A bounded versioned
successful-backup descriptor records one owned successful preimage and at most
one prior owned preimage pending retirement. Paths in records cannot select
arbitrary cleanup targets.

The newest verified preimage is registered/read back before the prior owned
preimage is retired. Cleanup rechecks directory identity, receipt digest,
expected file identities/hashes/sizes, and every allowed child. It never follows
links or recursively deletes unknown children. Unknown `.bak`, manual exports,
failed or unclassified transaction material are not adopted or deleted.

A bounded, exclusively created `.maintenance` witness remains present through
all descriptor publication, retirement, and required synchronization checkpoints.
Only after those checkpoints succeed is its exact owned file removed. A failed
witness creation/sync/removal or terminal descriptor/directory sync retains an
on-disk block (or the still-unregistered transaction material) and the current
session also gates writes on its maintenance warning. The witness is not a
replay journal and is never used to select or authenticate a vault.

There is deliberately no required directory sync after the final witness removal.
Thus readiness is not a claim that this cleanup is physically power-loss durable:
a later power loss can make a successfully removed witness reappear, conservatively
requesting maintenance again. It cannot erase the witness before the preceding
required checkpoints have succeeded. Keep the folder intact and use explicit
selected-copy authentication/restore-to-new when this warning appears.

A descriptor or cleanup failure after the verified commit is **success with a
maintenance warning**, not a failed save. Further modifying saves are blocked
until the user resolves the retained material. The deliberately conservative
first implementation does not silently resume partially completed cleanup on
restart. The actionable route is to keep the original folder intact and restore
an authenticated selected copy into a new file. This prevents repeated saves
from accumulating untracked successful transactions. Normal steady state is one
owned successful preimage; transitional registered retention is at most two.
Staging may require about three vault sizes of extra space, up to approximately
192 MiB at the 64 MiB vault limit, plus the prior successful backup.

## Locked recovery

Select “检查恢复副本” while locked. Manual path keystrokes remain editable and do
not start recovery scans or clear entered authentication fields. Inspection occurs
at startup, explicit open, or a committed open-file chooser selection.

On Windows, existing selected spellings use the same full-path normalization as
live sessions, including supported case-insensitive/8.3 aliases. Distinct files in
case-sensitive directories remain distinct; filenames are not globally lowercased.
A missing destination keeps its last known filename and physical parent, and
session-originated recovery uses that saved normalized destination.

The persistent sensitive-clipboard warning and its generation-bound manual
acknowledgment are shown in recovery even when storage/password errors replace
the status text. Missing or unsupported source observations from the non-editor
Save verification route invalidate the UI session and preserve the source cause
in its typed recovery information, just like changed source content.

Inspection is bounded to direct sibling transaction records. Registered successful backups are listed without a
false recovery alarm. Unknown material is shown, never replayed or selected by
its timestamp. An incomplete scan or bad descriptor is visible and blocks normal
opening until reviewed; a genuinely absent parent/file remains a normal open
error.

Select an encrypted source copy explicitly, enter that copy's password, and
choose a **nonexistent** destination. “验证并恢复到新文件” authenticates the
captured source bytes and copies only to a new destination. The source and
original recovery folder are read-only. Wrong passwords, corrupt sources and
occupied destinations preserve existing files. Password inputs are masked and
zeroizing; completion, cancellation, lock, monitor failure and navigation clear
or invalidate pending secret work. Native chooser results and form events carry
context guards. Windows recovery authentication requires the security monitor to
be ready, like normal unlock. After a successful recovery, the app remains locked
and points to the new file for a fresh unlock.

## API migration

`VaultSession::restore_encrypted_backup(..., false)` remains the restore-to-new
API. Its `overwrite=true` branch now rejects the request. Confirmed overwrite
uses `active_destination.restore_over_current(source, source_password)`, binding
the operation to the active destination's saved identity/hash/revision. On
success the caller adopts its returned, transaction-verified session directly;
it must not reopen outside the transaction or retain the old session. Import's
in-memory rollback does not downgrade disk disposition or reactivate a stale
preview after an external conflict.

## Evidence limits

Deterministic synthetic tests cover prepublication rejection, actual late
competing displacement, postpublication failure, synchronization boundaries,
retention faults, wrong/corrupt recovery sources, collisions, stale UI/chooser
results and process termination at prepublish/afterpublish/beforeverify. Process
kill tests demonstrate restart evidence, **not physical power-loss durability**.
Windows 1175/1176-with-backup/1177/unknown-error namespace tests are explicitly
models; native sharing tests run only on Windows. Cross-compiling the isolated
production platform module checks API typing, not Windows runtime behavior.

Linux syncs staged files and changed directories. Windows syncs supported file
handles and does not claim a directory-flush or unsupported
`REPLACEFILE_WRITE_THROUGH` guarantee. Windows ACL/sharing matrices, Windows 10
22H2, physical power loss and real IME/DPI/suspend timing still need native tests.
Crypto and storage remain synchronous in this batch; asynchronous preparation,
commit arbitration and master-password rewrap are separate subsequent work.
