;; EncryptionManager.clar
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-PUBLIC-KEY u101)
(define-constant ERR-INVALID-ENCRYPTED-KEY u102)
(define-constant ERR-KEY-NOT-FOUND u103)
(define-constant ERR-INVALID-KEY-TYPE u104)
(define-constant ERR-INVALID-KEY-SIZE u105)
(define-constant ERR-KEY-ALREADY-EXISTS u106)
(define-constant ERR-INVALID-USER u107)
(define-constant ERR-INVALID-ENTRY-ID u108)
(define-constant ERR-KEY-EXPIRED u109)
(define-constant ERR-INVALID-UPDATE-PARAM u110)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u111)
(define-constant ERR-INVALID-ENCRYPTION-MODE u112)
(define-constant ERR-INVALID-KDF-PARAMS u113)
(define-constant ERR-INVALID-IV u114)
(define-constant ERR-INVALID-TAG u115)
(define-constant ERR-INVALID-KEY-INDEX u116)
(define-constant ERR-INVALID-KEY-STATUS u117)
(define-constant ERR-INVALID-ROTATION-PERIOD u118)
(define-constant ERR-INVALID-BACKUP-KEY u119)

(define-data-var next-key-id uint u0)
(define-data-var default-key-rotation-period uint u365)
(define-data-var supported-encryption-modes (list 5 (string-ascii 16)) (list "AES-256-GCM" "CHACHA20-POLY1305"))
(define-data-var authority-contract (optional principal) none)
(define-data-var key-backup-enabled bool true)

(define-map UserPublicKeys
  principal
  {
    key-id: uint,
    public-key: (buff 64),
    key-type: (string-ascii 16),
    created-at: uint,
    status: bool
  }
)

(define-map EntryEncryptionKeys
  { user: principal, entry-id: uint }
  {
    key-id: uint,
    encrypted-key: (buff 128),
    iv: (buff 12),
    auth-tag: (buff 16),
    mode: (string-ascii 16),
    kdf-salt: (buff 32),
    kdf-iterations: uint,
    expires-at: (optional uint),
    rotated-at: uint,
    backup-key: (optional (buff 128))
  }
)

(define-map KeyRotationSchedule
  { user: principal, key-id: uint }
  {
    next-rotation: uint,
    period: uint,
    auto-rotate: bool,
    last-rotated: uint
  }
)

(define-map KeyAccessLog
  { user: principal, entry-id: uint, accessor: principal }
  {
    accessed-at: uint,
    key-id: uint,
    success: bool
  }
)

(define-read-only (get-user-public-key (user principal))
  (map-get? UserPublicKeys user)
)

(define-read-only (get-entry-encryption-key (user principal) (entry-id uint))
  (map-get? EntryEncryptionKeys { user: user, entry-id: entry-id })
)

(define-read-only (get-key-rotation-schedule (user principal) (key-id uint))
  (map-get? KeyRotationSchedule { user: user, key-id: key-id })
)

(define-read-only (is-encryption-mode-supported (mode (string-ascii 16)))
  (is-some (index-of (var-get supported-encryption-modes) mode))
)

(define-private (validate-public-key (key (buff 64)))
  (if (is-eq (len key) u64)
      (ok true)
      (err ERR-INVALID-PUBLIC-KEY))
)

(define-private (validate-encrypted-key (key (buff 128)))
  (if (is-eq (len key) u128)
      (ok true)
      (err ERR-INVALID-ENCRYPTED-KEY))
)

(define-private (validate-iv (iv (buff 12)))
  (if (is-eq (len iv) u12)
      (ok true)
      (err ERR-INVALID-IV))
)

(define-private (validate-auth-tag (tag (buff 16)))
  (if (is-eq (len tag) u16)
      (ok true)
      (err ERR-INVALID-TAG))
)

(define-private (validate-key-type (key-type (string-ascii 16)))
  (if (or (is-eq key-type "ed25519") (is-eq key-type "secp256k1"))
      (ok true)
      (err ERR-INVALID-KEY-TYPE))
)

(define-private (validate-entry-id (entry-id uint))
  (if (>= entry-id u0)
      (ok true)
      (err ERR-INVALID-ENTRY-ID))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (asserts! (not (is-eq contract-principal 'SP000000000000000000002Q6VF78)) (err ERR-INVALID-USER))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-default-key-rotation-period (new-period uint))
  (begin
    (asserts! (> new-period u0) (err ERR-INVALID-ROTATION-PERIOD))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set default-key-rotation-period new-period)
    (ok true)
  )
)

(define-public (toggle-key-backup (enabled bool))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set key-backup-enabled enabled)
    (ok true)
  )
)

(define-public (register-public-key (public-key (buff 64)) (key-type (string-ascii 16)))
  (let (
        (user tx-sender)
        (key-id (var-get next-key-id))
      )
    (try! (validate-public-key public-key))
    (try! (validate-key-type key-type))
    (asserts! (is-none (map-get? UserPublicKeys user)) (err ERR-KEY-ALREADY-EXISTS))
    (map-set UserPublicKeys user
      {
        key-id: key-id,
        public-key: public-key,
        key-type: key-type,
        created-at: block-height,
        status: true
      }
    )
    (var-set next-key-id (+ key-id u1))
    (print { event: "public-key-registered", user: user, key-id: key-id })
    (ok key-id)
  )
)

(define-public (store-entry-encryption-key
  (entry-id uint)
  (encrypted-key (buff 128))
  (iv (buff 12))
  (auth-tag (buff 16))
  (mode (string-ascii 16))
  (kdf-salt (buff 32))
  (kdf-iterations uint)
  (expires-at (optional uint))
  (backup-key (optional (buff 128)))
)
  (let (
        (user tx-sender)
        (key-id (var-get next-key-id))
      )
    (try! (validate-entry-id entry-id))
    (try! (validate-encrypted-key encrypted-key))
    (try! (validate-iv iv))
    (try! (validate-auth-tag auth-tag))
    (asserts! (is-encryption-mode-supported mode) (err ERR-INVALID-ENCRYPTION-MODE))
    (asserts! (is-some (map-get? UserPublicKeys user)) (err ERR-KEY-NOT-FOUND))
    (asserts! (is-none (map-get? EntryEncryptionKeys { user: user, entry-id: entry-id })) (err ERR-KEY-ALREADY-EXISTS))
    (match backup-key
      bk (try! (validate-encrypted-key bk))
      (ok true)
    )
    (map-set EntryEncryptionKeys { user: user, entry-id: entry-id }
      {
        key-id: key-id,
        encrypted-key: encrypted-key,
        iv: iv,
        auth-tag: auth-tag,
        mode: mode,
        kdf-salt: kdf-salt,
        kdf-iterations: kdf-iterations,
        expires-at: expires-at,
        rotated-at: block-height,
        backup-key: backup-key
      }
    )
    (map-set KeyRotationSchedule { user: user, key-id: key-id }
      {
        next-rotation: (+ block-height (var-get default-key-rotation-period)),
        period: (var-get default-key-rotation-period),
        auto-rotate: true,
        last-rotated: block-height
      }
    )
    (var-set next-key-id (+ key-id u1))
    (print { event: "entry-key-stored", user: user, entry-id: entry-id, key-id: key-id })
    (ok key-id)
  )
)

(define-public (rotate-entry-key
  (entry-id uint)
  (new-encrypted-key (buff 128))
  (new-iv (buff 12))
  (new-auth-tag (buff 16))
  (new-backup-key (optional (buff 128)))
)
  (let (
        (user tx-sender)
        (existing (map-get? EntryEncryptionKeys { user: user, entry-id: entry-id }))
      )
    (try! (validate-entry-id entry-id))
    (try! (validate-encrypted-key new-encrypted-key))
    (try! (validate-iv new-iv))
    (try! (validate-auth-tag new-auth-tag))
    (match new-backup-key
      bk (try! (validate-encrypted-key bk))
      (ok true)
    )
    (match existing
      e
        (let ((key-id (get key-id e)))
          (map-set EntryEncryptionKeys { user: user, entry-id: entry-id }
            (merge e {
              encrypted-key: new-encrypted-key,
              iv: new-iv,
              auth-tag: new-auth-tag,
              rotated-at: block-height,
              backup-key: new-backup-key
            })
          )
          (map-set KeyRotationSchedule { user: user, key-id: key-id }
            (merge (unwrap! (map-get? KeyRotationSchedule { user: user, key-id: key-id }) (err ERR-KEY-NOT-FOUND)) {
              next-rotation: (+ block-height (get period (unwrap! (map-get? KeyRotationSchedule { user: user, key-id: key-id }) (err ERR-KEY-NOT-FOUND)))),
              last-rotated: block-height
            })
          )
          (print { event: "key-rotated", user: user, entry-id: entry-id, key-id: key-id })
          (ok true)
        )
      (err ERR-KEY-NOT-FOUND)
    )
  )
)

(define-public (log-key-access (entry-id uint) (accessor principal) (success bool))
  (let (
        (user tx-sender)
      )
    (try! (validate-entry-id entry-id))
    (asserts! (is-some (map-get? EntryEncryptionKeys { user: user, entry-id: entry-id })) (err ERR-KEY-NOT-FOUND))
    (map-set KeyAccessLog { user: user, entry-id: entry-id, accessor: accessor }
      {
        accessed-at: block-height,
        key-id: (get key-id (unwrap! (map-get? EntryEncryptionKeys { user: user, entry-id: entry-id }) (err ERR-KEY-NOT-FOUND))),
        success: success
      }
    )
    (ok true)
  )
)

(define-public (get-key-access-log (user principal) (entry-id uint) (accessor principal))
  (map-get? KeyAccessLog { user: user, entry-id: entry-id, accessor: accessor })
)

(define-public (check-key-rotation-due (user principal) (key-id uint))
  (match (map-get? KeyRotationSchedule { user: user, key-id: key-id })
    s (ok (>= block-height (get next-rotation s)))
    (err ERR-KEY-NOT-FOUND)
  )
)