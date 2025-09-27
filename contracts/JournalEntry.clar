(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-HASH u101)
(define-constant ERR-ENTRY-NOT-FOUND u102)
(define-constant ERR-INVALID-MOOD-RATING u103)
(define-constant ERR-INVALID-CONTENT u104)
(define-constant ERR-INVALID-TIMESTAMP u105)
(define-constant ERR-ENTRY-ALREADY-EXISTS u106)
(define-constant ERR-MAX-ENTRIES-EXCEEDED u107)
(define-constant ERR-INVALID-USER u108)
(define-constant ERR-PERMISSION-DENIED u109)
(define-constant ERR-INVALID-KEY u110)
(define-constant ERR-ENTRY-LOCKED u111)
(define-constant ERR-INVALID-CATEGORY u112)
(define-constant ERR-INVALID-TAG u113)
(define-constant ERR-INVALID-STATUS u114)
(define-constant ERR-INVALID-UPDATE-PARAM u115)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u116)
(define-constant ERR-INVALID-MAX-ENTRIES u117)
(define-constant ERR-INVALID-RETENTION-PERIOD u118)
(define-constant ERR-INVALID-ENCRYPTION-SCHEME u119)
(define-constant ERR-INVALID-SHARE-LEVEL u120)

(define-data-var next-entry-id uint u0)
(define-data-var max-entries-per-user uint u1000)
(define-data-var retention-period uint u365)
(define-data-var authority-contract (optional principal) none)
(define-data-var encryption-scheme (string-ascii 32) "AES-256-GCM")
(define-data-var entry-fee uint u10)

(define-map Entries
  { user: principal, entry-id: uint }
  {
    encrypted-content: (buff 1024),
    timestamp: uint,
    mood-rating: uint,
    content-hash: (buff 32),
    category: (string-utf8 50),
    tags: (list 10 (string-utf8 20)),
    status: bool,
    share-level: uint
  }
)

(define-map EntryUpdates
  { user: principal, entry-id: uint }
  {
    update-timestamp: uint,
    updater: principal,
    previous-hash: (buff 32)
  }
)

(define-map UserEntryCounts
  principal
  uint
)

(define-map SharedAccess
  { user: principal, entry-id: uint, therapist: principal }
  bool
)

(define-read-only (get-entry (user principal) (id uint))
  (map-get? Entries { user: user, entry-id: id })
)

(define-read-only (get-entry-updates (user principal) (id uint))
  (map-get? EntryUpdates { user: user, entry-id: id })
)

(define-read-only (get-user-entry-count (user principal))
  (default-to u0 (map-get? UserEntryCounts user))
)

(define-read-only (is-entry-shared (user principal) (id uint) (therapist principal))
  (default-to false (map-get? SharedAccess { user: user, entry-id: id, therapist: therapist }))
)

(define-private (validate-content (content (buff 1024)))
  (if (> (len content) u0)
      (ok true)
      (err ERR-INVALID-CONTENT))
)

(define-private (validate-mood-rating (rating uint))
  (if (and (>= rating u1) (<= rating u10))
      (ok true)
      (err ERR-INVALID-MOOD-RATING))
)

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-HASH))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
)

(define-private (validate-category (cat (string-utf8 50)))
  (if (and (> (len cat) u0) (<= (len cat) u50))
      (ok true)
      (err ERR-INVALID-CATEGORY))
)

(define-private (validate-tags (tags (list 10 (string-utf8 20))))
  (fold validate-tag tags (ok true))
)

(define-private (validate-tag (tag (string-utf8 20)) (acc (response bool uint)))
  (match acc
    ok-val
    (if (and (> (len tag) u0) (<= (len tag) u20))
        (ok true)
        (err ERR-INVALID-TAG))
    err-val acc
  )
)

(define-private (validate-status (status bool))
  (ok true)
)

(define-private (validate-share-level (level uint))
  (if (<= level u3)
      (ok true)
      (err ERR-INVALID-SHARE-LEVEL))
)

(define-private (validate-user (user principal))
  (if (not (is-eq user 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR-INVALID-USER))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-user contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-entries-per-user (new-max uint))
  (begin
    (asserts! (> new-max u0) (err ERR-INVALID-MAX-ENTRIES))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set max-entries-per-user new-max)
    (ok true)
  )
)

(define-public (set-retention-period (new-period uint))
  (begin
    (asserts! (> new-period u0) (err ERR-INVALID-RETENTION-PERIOD))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set retention-period new-period)
    (ok true)
  )
)

(define-public (set-encryption-scheme (new-scheme (string-ascii 32)))
  (begin
    (asserts! (> (len new-scheme) u0) (err ERR-INVALID-ENCRYPTION-SCHEME))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set encryption-scheme new-scheme)
    (ok true)
  )
)

(define-public (set-entry-fee (new-fee uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set entry-fee new-fee)
    (ok true)
  )
)

(define-public (add-entry
  (encrypted-content (buff 1024))
  (mood-rating uint)
  (content-hash (buff 32))
  (category (string-utf8 50))
  (tags (list 10 (string-utf8 20)))
  (status bool)
  (share-level uint)
)
  (let (
        (user tx-sender)
        (entry-id (var-get next-entry-id))
        (current-count (get-user-entry-count user))
        (max-entries (var-get max-entries-per-user))
        (authority (var-get authority-contract))
      )
    (asserts! (< current-count max-entries) (err ERR-MAX-ENTRIES-EXCEEDED))
    (try! (validate-content encrypted-content))
    (try! (validate-mood-rating mood-rating))
    (try! (validate-hash content-hash))
    (try! (validate-category category))
    (try! (validate-tags tags))
    (try! (validate-status status))
    (try! (validate-share-level share-level))
    (asserts! (is-none (map-get? Entries { user: user, entry-id: entry-id })) (err ERR-ENTRY-ALREADY-EXISTS))
    (let ((authority-recipient (unwrap! authority (err ERR-AUTHORITY-NOT-VERIFIED))))
      (try! (stx-transfer? (var-get entry-fee) tx-sender authority-recipient))
    )
    (map-set Entries { user: user, entry-id: entry-id }
      {
        encrypted-content: encrypted-content,
        timestamp: block-height,
        mood-rating: mood-rating,
        content-hash: content-hash,
        category: category,
        tags: tags,
        status: status,
        share-level: share-level
      }
    )
    (map-set UserEntryCounts user (+ current-count u1))
    (var-set next-entry-id (+ entry-id u1))
    (print { event: "entry-added", user: user, id: entry-id })
    (ok entry-id)
  )
)

(define-public (update-entry
  (entry-id uint)
  (new-encrypted-content (buff 1024))
  (new-mood-rating uint)
  (new-content-hash (buff 32))
)
  (let (
        (user tx-sender)
        (entry (map-get? Entries { user: user, entry-id: entry-id }))
      )
    (match entry
      e
        (begin
          (asserts! (is-eq tx-sender user) (err ERR-NOT-AUTHORIZED))
          (try! (validate-content new-encrypted-content))
          (try! (validate-mood-rating new-mood-rating))
          (try! (validate-hash new-content-hash))
          (map-set Entries { user: user, entry-id: entry-id }
            {
              encrypted-content: new-encrypted-content,
              timestamp: block-height,
              mood-rating: new-mood-rating,
              content-hash: new-content-hash,
              category: (get category e),
              tags: (get tags e),
              status: (get status e),
              share-level: (get share-level e)
            }
          )
          (map-set EntryUpdates { user: user, entry-id: entry-id }
            {
              update-timestamp: block-height,
              updater: tx-sender,
              previous-hash: (get content-hash e)
            }
          )
          (print { event: "entry-updated", user: user, id: entry-id })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-public (grant-access (entry-id uint) (therapist principal))
  (let (
        (user tx-sender)
        (entry (map-get? Entries { user: user, entry-id: entry-id }))
      )
    (match entry
      e
        (begin
          (asserts! (is-eq tx-sender user) (err ERR-NOT-AUTHORIZED))
          (asserts! (not (is-entry-shared user entry-id therapist)) (err ERR_PERMISSION-DENIED))
          (map-set SharedAccess { user: user, entry-id: entry-id, therapist: therapist } true)
          (print { event: "access-granted", user: user, id: entry-id, therapist: therapist })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-public (revoke-access (entry-id uint) (therapist principal))
  (let (
        (user tx-sender)
        (entry (map-get? Entries { user: user, entry-id: entry-id }))
      )
    (match entry
      e
        (begin
          (asserts! (is-eq tx-sender user) (err ERR-NOT-AUTHORIZED))
          (asserts! (is-entry-shared user entry-id therapist) (err ERR_PERMISSION-DENIED))
          (map-delete SharedAccess { user: user, entry-id: entry-id, therapist: therapist })
          (print { event: "access-revoked", user: user, id: entry-id, therapist: therapist })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-public (delete-entry (entry-id uint))
  (let (
        (user tx-sender)
        (entry (map-get? Entries { user: user, entry-id: entry-id }))
      )
    (match entry
      e
        (begin
          (asserts! (is-eq tx-sender user) (err ERR-NOT-AUTHORIZED))
          (map-delete Entries { user: user, entry-id: entry-id })
          (map-delete EntryUpdates { user: user, entry-id: entry-id })
          (map-set UserEntryCounts user (- (get-user-entry-count user) u1))
          (print { event: "entry-deleted", user: user, id: entry-id })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-read-only (get-total-entries)
  (ok (var-get next-entry-id))
)

(define-public (check-entry-existence (user principal) (id uint))
  (ok (is-some (map-get? Entries { user: user, entry-id: id })))
)