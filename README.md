# 🧠 Decentralized Mental Health Journaling App

Welcome to a secure, privacy-first platform for mental health journaling! This Web3 project addresses the real-world problem of maintaining personal mental health records in a confidential manner while enabling selective sharing with trusted therapists. In a world where data breaches and privacy concerns are rampant, this app uses the Stacks blockchain and Clarity smart contracts to ensure entries are encrypted, immutable, and only accessible via explicit user permissions. No central authority holds your data—empowering individuals to control their mental health journey.

## ✨ Features

🔒 End-to-end encrypted journal entries stored on-chain  
📅 Timestamped and immutable logging of moods, thoughts, and reflections  
👥 Permissioned sharing: Grant/revoke access to specific entries for verified therapists  
🛡️ Therapist verification system to prevent unauthorized access  
📊 Analytics dashboard for users (off-chain, but powered by on-chain data)  
🚨 Notification system for shared entries and access requests  
🔑 Key recovery mechanism for lost access without compromising security  
✅ Compliance with privacy standards through decentralized auditing  
💰 Optional micropayments for premium therapist consultations (using STX tokens)  
🛑 Emergency revocation of all shares in case of account compromise

## 🛠 How It Works

**For Users (Journalers)**  
- Register your account and generate a personal encryption key pair.  
- Create encrypted journal entries with details like mood ratings, text reflections, and timestamps.  
- Store entries on the blockchain via the JournalEntry contract—only you can decrypt them initially.  
- When ready to share, grant permissions to a verified therapist for specific entries or date ranges.  
- Monitor access logs and revoke permissions at any time.  
- Use the recovery system if needed, without exposing data to third parties.

**For Therapists**  
- Get verified through a decentralized credential check (e.g., linking professional licenses).  
- Request access to a patient's shared entries.  
- Receive notifications when access is granted.  
- View decrypted entries (with patient-provided keys) for sessions.  
- Log session notes securely, tied to the shared entry.  

**Technical Flow**  
1. User registers and sets up keys.  
2. Entries are hashed and encrypted before storage.  
3. Permissions are managed via NFTs representing access rights.  
4. All interactions are atomic and audited on-chain for transparency.

## 📜 Smart Contracts (8 in Total)

This project is built using Clarity on the Stacks blockchain. Here's an overview of the 8 smart contracts that power the app, each handling a specific aspect for modularity and security:

1. **UserRegistry.clar**: Handles user registration, profile creation, and basic authentication. Maps principals to user IDs and stores public keys.  
2. **JournalEntry.clar**: Core contract for creating, storing, and retrieving encrypted journal entries. Includes functions for adding entries with timestamps and hashes.  
3. **EncryptionManager.clar**: Manages encryption keys, including key generation, storage of public keys, and secure key exchange for sharing.  
4. **AccessControl.clar**: Implements permissioned access using ACLs (Access Control Lists). Allows granting/revoking access to specific entries via NFTs.  
5. **TherapistVerifier.clar**: Verifies therapist credentials through on-chain proofs (e.g., zero-knowledge proofs for licenses) and maintains a registry of approved therapists.  
6. **NotificationHub.clar**: Sends on-chain notifications for access requests, grants, and revocations. Integrates with off-chain push notifications.  
7. **AuditLogger.clar**: Logs all access events immutably for auditing, ensuring compliance and allowing users to review who viewed what.  
8. **RecoveryVault.clar**: Provides a secure recovery mechanism for lost keys, using multi-signature or time-locked vaults without exposing data.

These contracts interact seamlessly—for example, JournalEntry calls AccessControl to check permissions before allowing reads. Deploy them in sequence starting with UserRegistry.

## 🚀 Getting Started

1. Set up a Stacks wallet and Clarity development environment.  
2. Deploy the contracts to a testnet.  
3. Build a frontend (e.g., with React) to interact with the contracts via the Stacks.js library.  
4. Test encryption flows using libraries like Web Crypto API for client-side ops.

This project not only solves privacy issues in mental health tracking but also fosters trust in therapeutic relationships through blockchain transparency. Let's build a healthier world, one encrypted entry at a time!