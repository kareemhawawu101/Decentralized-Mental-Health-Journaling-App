;; AccessControl.clar
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-ENTRY-NOT-FOUND u101)
(define-constant ERR-INVALID-PERMISSION u102)
(define-constant ERR-ALREADY-GRANTED u103)
(define-constant ERR-NOT-GRANTED u104)
(define-constant ERR-INVALID-EXPIRY u105)
(define-constant ERR-PERMISSION-EXPIRED u106)
(define-constant ERR-INVALID-LEVEL u107)
(define-constant ERR-THERAPIST-NOT-VERIFIED u108)
(define-constant ERR-INVALID-TIMESTAMP u109)
(define-constant ERR-MAX-SHARES-EXCEEDED u110)
(define-constant ERR-INVALID-USER u111)
(define-constant ERR-INVALID-ENTRY-ID u112)
(define-constant ERR-INVALID-THERAPIST u113)
(define-constant ERR-INVALID-UPDATE-PARAM u114)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u115)
(define-constant ERR-INVALID-MAX-SHARES u116)
(define-constant ERR-INVALID-DEFAULT-LEVEL u117)
(define-constant ERR-INVALID-AUDIT-LOG u118)
(define-constant ERR-INVALID-KEY u119)

(define-data-var next-permission-id uint u0)
(define-data-var max-shares-per-entry uint u10)
(define-data-var default-permission-level uint u1)
(define-data-var authority-contract (optional principal) none)
(define-data-var audit-log-enabled bool true)

(define-map Permissions
  { user: principal,entry-id: uint, therapist: principal }
  {
    permission-id: uint,
    level: uint,
    granted-at: uint,
    expires-at: (optional uint),
    status: bool,
    last-accessed: (optional uint)
  }
)

(define-map PermissionHistory
  { permission-id: uint }
  {
    user: principal,
    entry-id: uint,
    therapist: principal,
    old-level: uint,
    new-level: uint,
    updated-at: uint,
    updater: principal
  }
)

(define-map TherapistRegistry
  principal
  {
    verified: bool,
    license-hash: (buff 32),
    verified-at: uint,
    status: bool
  }
)

(define-map UserShareCounts
  { user: principal, entry-id: uint }
  uint
)

(define-read-only (get-permission (user principal) (entry-id uint) (therapist principal))
  (map-get? Permissions { user: user, entry-id: entry-id, therapist: therapist })
)

(define-read-only (get-permission-history (permission-id uint))
  (map-get? PermissionHistory { permission-id: permission-id })
)

(define-read-only (is-therapist-verified (therapist principal))
  (match (map-get? TherapistRegistry therapist)
    t (get verified t)
    false
  )
)

(define-read-only (get-user-share-count (user principal) (entry-id uint))
  (default-to u0 (map-get? UserShareCounts { user: user, entry-id: entry-id }))
)

(define-private (validate-permission-level (level uint))
  (if (and (>= level u1) (<= level u3))
      (ok true)
      (err ERR-INVALID-LEVEL))
)

(define-private (validate-expiry (expiry (optional uint)))
  (match expiry
    exp (if (> exp block-height) (ok true) (err ERR-INVALID-EXPIRY))
    (ok true)
  )
)

(define-private (validate-therapist (therapist principal))
  (if (and (not (is-eq therapist tx-sender)) (not (is-eq therapist 'SP000000000000000000002Q6VF78)))
      (ok true)
      (err ERR-INVALID-THERAPIST))
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

(define-public (set-max-shares-per-entry (new-max uint))
  (begin
    (asserts! (> new-max u0) (err ERR-INVALID-MAX-SHARES))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set max-shares-per-entry new-max)
    (ok true)
  )
)

(define-public (set-default-permission-level (new-level uint))
  (begin
    (try! (validate-permission-level new-level))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set default-permission-level new-level)
    (ok true)
  )
)

(define-public (toggle-audit-log (enabled bool))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set audit-log-enabled enabled)
    (ok true)
  )
)

(define-public (verify-therapist (therapist principal) (license-hash (buff 32)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (asserts! (is-eq (len license-hash) u32) (err ERR-INVALID-KEY))
    (map-set TherapistRegistry therapist
      {
        verified: true,
        license-hash: license-hash,
        verified-at: block-height,
        status: true
      }
    )
    (ok true)
  )
)

(define-public (grant-permission
  (entry-id uint)
  (therapist principal)
  (level uint)
  (expires-at (optional uint))
)
  (let (
        (user tx-sender)
        (permission-id (var-get next-permission-id))
        (current-count (get-user-share-count user entry-id))
        (max-shares (var-get max-shares-per-entry))
      )
    (try! (validate-entry-id entry-id))
    (try! (validate-therapist therapist))
    (try! (validate-permission-level level))
    (try! (validate-expiry expires-at))
    (asserts! (< current-count max-shares) (err ERR-MAX-SHARES-EXCEEDED))
    (asserts! (is-none (map-get? Permissions { user: user, entry-id: entry-id, therapist: therapist })) (err ERR-ALREADY-GRANTED))
    (asserts! (is-therapist-verified therapist) (err ERR-THERAPIST-NOT-VERIFIED))
    (map-set Permissions { user: user, entry-id: entry-id, therapist: therapist }
      {
        permission-id: permission-id,
        level: level,
        granted-at: block-height,
        expires-at: expires-at,
        status: true,
        last-accessed: none
      }
    )
    (map-set UserShareCounts { user: user, entry-id: entry-id } (+ current-count u1))
    (var-set next-permission-id (+ permission-id u1))
    (if (var-get audit-log-enabled)
        (map-set PermissionHistory { permission-id: permission-id }
          {
            user: user,
            entry-id: entry-id,
            therapist: therapist,
            old-level: u0,
            new-level: level,
            updated-at: block-height,
            updater: tx-sender
          }
        )
        true
    )
    (print { event: "permission-granted", user: user, entry-id: entry-id, therapist: therapist, level: level })
    (ok permission-id)
  )
)

(define-public (update-permission-level
  (entry-id uint)
  (therapist principal)
  (new-level uint)
)
  (let (
        (user tx-sender)
        (permission (map-get? Permissions { user: user, entry-id: entry-id, therapist: therapist }))
      )
    (try! (validate-entry-id entry-id))
    (try! (validate-permission-level new-level))
    (match permission
      p
        (let ((permission-id (get permission-id p)))
          (asserts! (get status p) (err ERR-NOT-GRANTED))
          (map-set Permissions { user: user, entry-id: entry-id, therapist: therapist }
            (merge p {
              level: new-level,
              last-accessed: (some block-height)
            })
          )
          (if (var-get audit-log-enabled)
              (map-set PermissionHistory { permission-id: permission-id }
                {
                  user: user,
                  entry-id: entry-id,
                  therapist: therapist,
                  old-level: (get level p),
                  new-level: new-level,
                  updated-at: block-height,
                  updater: tx-sender
                }
              )
              true
          )
          (print { event: "permission-updated", user: user, entry-id: entry-id, therapist: therapist, new-level: new-level })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-public (revoke-permission
  (entry-id uint)
  (therapist principal)
)
  (let (
        (user tx-sender)
        (permission (map-get? Permissions { user: user, entry-id: entry-id, therapist: therapist }))
      )
    (try! (validate-entry-id entry-id))
    (match permission
      p
        (let ((permission-id (get permission-id p)))
          (asserts! (get status p) (err ERR-NOT-GRANTED))
          (map-set Permissions { user: user, entry-id: entry-id, therapist: therapist }
            (merge p { status: false, last-accessed: (some block-height) })
          )
          (let ((current-count (get-user-share-count user entry-id)))
            (map-set UserShareCounts { user: user, entry-id: entry-id } (- current-count u1))
          )
          (if (var-get audit-log-enabled)
              (map-set PermissionHistory { permission-id: permission-id }
                {
                  user: user,
                  entry-id: entry-id,
                  therapist: therapist,
                  old-level: (get level p),
                  new-level: u0,
                  updated-at: block-height,
                  updater: tx-sender
                }
              )
              true
          )
          (print { event: "permission-revoked", user: user, entry-id: entry-id, therapist: therapist })
          (ok true)
        )
      (err ERR-ENTRY-NOT-FOUND)
    )
  )
)

(define-public (check-access
  (user principal)
  (entry-id uint)
  (therapist principal)
)
  (let ((permission (map-get? Permissions { user: user, entry-id: entry-id, therapist: therapist })))
    (match permission
      p
        (begin
          (asserts! (get status p) (err ERR-PERMISSION-DENIED))
          (match (get expires-at p)
            exp (asserts! (>= exp block-height) (err ERR-PERMISSION-EXPIRED))
            true
          )
          (map-set Permissions { user: user, entry-id: entry-id, therapist: therapist }
            (merge p { last-accessed: (some block-height) })
          )
          (ok (get level p))
        )
      (err ERR-NOT-GRANTED)
    )
  )
)

(define-public (get-active-shares (user principal) (entry-id uint))
  (ok (get-user-share-count user entry-id))
)

(define-public (list-permissions-for-entry (user principal) (entry-id uint))
  (ok (filter
       (lambda (key value) (and (is-eq (get user key) user) (is-eq (get entry-id key) entry-id) (get status value)))
       Permissions
     ))
)