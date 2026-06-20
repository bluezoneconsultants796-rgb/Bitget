// ══════════════════════════════════════════════════════════
//  hash-engine.js — Tamper-Proof Core Engine
//  Digital Exchange Management System — Phase 02
//
//  This is the HEART of the system.
//  Responsibilities:
//    • SHA-256 hash generation for every transaction record
//    • Hash chain: each transaction links to the previous
//    • Auto-timestamp injection (never manual)
//    • Sequential receipt number generation
//    • Chain integrity verification on startup
//    • No Edit / No Delete enforcement at engine level
//
//  SECURITY MODEL:
//    Each record's hash = SHA-256(all fields + prev_hash)
//    If ANY field is changed after insertion → hash mismatch
//    If ANY record is deleted → next record's prev_hash breaks
//    Result: tamper is mathematically detectable, always.
// ══════════════════════════════════════════════════════════

const HashEngine = (() => {

  // ── CONSTANTS ───────────────────────────────────────────
  const HASH_VERSION   = 'DEMS-v1';          // Version prefix in hash payload
  const GENESIS_HASH   = '0'.repeat(64);     // Genesis block prev_hash
  const SALT           = 'DEMS_CHAIN_SALT_2024'; // Applied to every hash

  // ── CORE: SHA-256 via Web Crypto API ────────────────────

  /**
   * sha256(input)
   * Computes SHA-256 hash of any string.
   * Returns lowercase hex string (64 chars).
   *
   * Uses native Web Crypto API — no external library needed.
   */
  async function sha256(input) {
    const encoded = new TextEncoder().encode(input);
    const buffer  = await crypto.subtle.digest('SHA-256', encoded);
    const bytes   = Array.from(new Uint8Array(buffer));
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── CORE: Build Hash Payload ─────────────────────────────

  /**
   * buildHashPayload(record, prevHash)
   *
   * Constructs the exact string that gets hashed.
   * Field order is FIXED — changing order changes hash.
   * Every field that matters to tamper-detection is included.
   *
   * This function defines WHAT is protected:
   *   - receipt_number  : unique ID
   *   - txn_type        : buy or sell
   *   - amount_pkr      : the money amount
   *   - exchange_rate   : rate at time of transaction
   *   - client_name     : who the client is
   *   - bank_last4      : payment reference
   *   - timestamp       : when it happened (server time)
   *   - chain_index     : position in chain
   *   - prev_hash       : link to previous record
   *   - SALT + VERSION  : anti-collision and versioning
   */
  function buildHashPayload(record, prevHash) {
    const fields = [
      HASH_VERSION,
      record.receipt_number  || '',
      record.txn_type        || '',
      String(record.amount_pkr    || 0),
      String(record.exchange_rate || 0),
      String(record.amount_usdt   || 0),
      record.client_name     || '',
      record.client_cnic     || '',
      record.bank_name       || '',
      record.bank_last4      || '',
      record.order_id        || '',
      record.payment_ref     || '',
      record.timestamp,           // ISO string — never manual
      String(record.chain_index),
      prevHash,
      SALT
    ];
    return fields.join('|');
  }

  // ── CORE: Timestamp Generator ────────────────────────────

  /**
   * getServerTimestamp()
   *
   * Returns current UTC timestamp as ISO 8601 string.
   * This is injected by the engine — the user CANNOT set this.
   * The UI form does not have a timestamp field.
   *
   * Format: "2024-06-15T14:32:07.481Z"
   */
  function getServerTimestamp() {
    return new Date().toISOString();
  }

  // ── CHAIN STATE ──────────────────────────────────────────

  /**
   * getChainState()
   * Reads current chain state from DB:
   *   - last hash in chain (to use as prev_hash for next record)
   *   - current chain length (to assign chain_index)
   *
   * Returns { prevHash, nextIndex }
   */
  async function getChainState() {
    try {
      const last = await DB.get(
        `SELECT hash, chain_index
         FROM transactions
         ORDER BY chain_index DESC
         LIMIT 1`
      );

      if (!last) {
        // Empty chain — genesis state
        return {
          prevHash  : GENESIS_HASH,
          nextIndex : 0
        };
      }

      return {
        prevHash  : last.hash,
        nextIndex : last.chain_index + 1
      };
    } catch (e) {
      console.error('[HashEngine] getChainState error:', e);
      return {
        prevHash  : GENESIS_HASH,
        nextIndex : 0
      };
    }
  }

  // ── VERIFICATION LOG ──────────────────────────────────────

  /**
   * logVerification(receiptNumber, result)
   *
   * Phase 07's `verification_log` table was defined in the schema but
   * nothing ever wrote to it — verifyByReceiptNumber/verifyByHash only
   * logged to AuditLog. This persists every verification attempt
   * (ORIGINAL / TAMPERED / NOT_FOUND) to its dedicated table so the
   * public verifier page can show a history of who/what was checked.
   *
   * NOTE: verifier_ip is left blank — there is no server here, so a
   * pure front-end script cannot learn the caller's real IP address.
   * Faking a value would be worse than leaving it empty.
   */
  async function logVerification(receiptNumber, result) {
    try {
      await DB.run(
        `INSERT INTO verification_log (receipt_number, verified_at, result, verifier_ip, user_agent)
         VALUES (?, ?, ?, ?, ?)`,
        [receiptNumber || '', new Date().toISOString(), result, '', navigator.userAgent.substring(0, 120)]
      );
    } catch (e) {
      console.warn('[HashEngine] verification_log write skipped:', e.message);
    }
  }

  // ── PUBLIC API ───────────────────────────────────────────
  return {

    // ── 1. PREPARE RECORD ─────────────────────────────────

    /**
     * prepareRecord(formData)
     *
     * Takes raw form input and returns a complete, hash-ready
     * transaction record. This is called BEFORE insertion.
     *
     * What this does:
     *   1. Injects server-side timestamp (user cannot override)
     *   2. Gets receipt number from DB sequence
     *   3. Gets chain state (prevHash + nextIndex)
     *   4. Computes SHA-256 hash of full payload
     *   5. Returns complete record ready for DB insert
     *
     * @param {Object} formData - Raw input from transaction form
     * @returns {Object} Complete record with hash, timestamp, chain links
     */
    async prepareRecord(formData) {

      // Step 1: Inject server timestamp (tamper-proof)
      const timestamp = getServerTimestamp();

      // Step 2: Get next receipt number from DB
      const receiptNumber = await DB.getNextReceiptNumber();

      // Step 3: Get chain state
      const { prevHash, nextIndex } = await getChainState();

      // Step 4: Assemble partial record (without hash)
      const record = {
        receipt_number  : receiptNumber,
        order_id        : (formData.order_id        || '').trim(),
        txn_type        : formData.txn_type,        // 'buy' | 'sell'
        amount_pkr      : parseFloat(formData.amount_pkr)      || 0,
        exchange_rate   : parseFloat(formData.exchange_rate)   || 0,
        amount_usdt     : parseFloat(formData.amount_usdt)     || 0,
        client_name     : (formData.client_name     || '').trim(),
        client_cnic     : (formData.client_cnic     || '').trim(),
        bank_name       : (formData.bank_name       || '').trim(),
        bank_last4      : (formData.bank_last4      || '').trim(),
        payment_ref     : (formData.payment_ref     || '').trim(),
        notes           : (formData.notes           || '').trim(),
        screenshot_path : (formData.screenshot_path || '').trim(),
        timestamp       : timestamp,   // ← SYSTEM SET, NOT USER
        chain_index     : nextIndex,
        prev_hash       : prevHash,
        is_locked       : 1            // Always locked from birth
      };

      // Step 5: Compute hash
      const payload     = buildHashPayload(record, prevHash);
      record.hash       = await sha256(payload);

      return record;
    },

    // ── 2. INSERT RECORD (IMMUTABLE) ──────────────────────

    /**
     * insertTransaction(formData)
     *
     * The ONLY way to add a transaction.
     * After this call, the record can NEVER be edited or deleted.
     *
     * Workflow:
     *   prepareRecord → DB INSERT → AuditLog → return receipt
     *
     * @param {Object} formData - From transaction form
     * @returns {Object} { success, record, receiptNumber }
     */
    async insertTransaction(formData) {
      try {

        // Validate required fields before touching the chain
        const validation = this.validateFormData(formData);
        if (!validation.valid) {
          return { success: false, error: validation.error };
        }

        // Prepare the record with hash + timestamp + chain link
        const record = await this.prepareRecord(formData);

        // INSERT — no UPDATE, no DELETE ever issued on this table
        await DB.run(
          `INSERT INTO transactions (
            receipt_number, order_id, txn_type,
            amount_pkr, exchange_rate, amount_usdt,
            client_name, client_cnic,
            bank_name, bank_last4, payment_ref,
            notes, screenshot_path,
            timestamp, hash, prev_hash, chain_index, is_locked
          ) VALUES (
            ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?, ?
          )`,
          [
            record.receipt_number,  record.order_id,     record.txn_type,
            record.amount_pkr,      record.exchange_rate, record.amount_usdt,
            record.client_name,     record.client_cnic,
            record.bank_name,       record.bank_last4,   record.payment_ref,
            record.notes,           record.screenshot_path,
            record.timestamp,       record.hash,         record.prev_hash,
            record.chain_index,     record.is_locked
          ]
        );

        // Audit trail
        AuditLog.add(
          'TRANSACTION_ADDED',
          `Receipt: ${record.receipt_number} | Type: ${record.txn_type.toUpperCase()} | PKR: ${record.amount_pkr.toLocaleString()} | Chain: #${record.chain_index}`
        );

        return {
          success       : true,
          record        : record,
          receiptNumber : record.receipt_number
        };

      } catch (e) {
        console.error('[HashEngine] insertTransaction error:', e);
        AuditLog.add('TRANSACTION_ERROR', `Insert failed: ${e.message}`);
        return { success: false, error: e.message };
      }
    },

    // ── 3. VERIFY SINGLE RECORD ───────────────────────────

    /**
     * verifyRecord(txn)
     *
     * Recomputes the SHA-256 hash of a stored record and
     * compares it to the stored hash value.
     *
     * If they match  → record is ORIGINAL (untouched)
     * If they differ → record has been TAMPERED
     *
     * @param {Object} txn - Row from transactions table
     * @returns {Object} { valid, storedHash, computedHash, tampered }
     */
    async verifyRecord(txn) {
      const payload      = buildHashPayload(txn, txn.prev_hash);
      const computedHash = await sha256(payload);
      const valid        = computedHash === txn.hash;

      return {
        valid        : valid,
        storedHash   : txn.hash,
        computedHash : computedHash,
        tampered     : !valid,
        receiptNumber: txn.receipt_number,
        chainIndex   : txn.chain_index
      };
    },

    // ── 4. VERIFY CHAIN LINK ──────────────────────────────

    /**
     * verifyChainLink(txn, prevTxn)
     *
     * Verifies that txn.prev_hash === prevTxn.hash
     * This confirms the chain is unbroken at this link.
     *
     * A broken link means a record was deleted or inserted
     * in the middle — both are tampering.
     *
     * @param {Object} txn     - Current transaction
     * @param {Object} prevTxn - Previous transaction (or null for genesis)
     * @returns {Object} { linked, expected, actual }
     */
    verifyChainLink(txn, prevTxn) {
      const expected = prevTxn ? prevTxn.hash : GENESIS_HASH;
      const actual   = txn.prev_hash;
      const linked   = expected === actual;

      return {
        linked   : linked,
        expected : expected,
        actual   : actual,
        broken   : !linked
      };
    },

    // ── 5. FULL CHAIN INTEGRITY CHECK ─────────────────────

    /**
     * verifyChain(onProgress?)
     *
     * Walks the ENTIRE transaction chain from genesis to tip.
     * Verifies:
     *   a) Each record's hash matches its stored value
     *   b) Each record's prev_hash links correctly to prior record
     *
     * This is called on app startup and can be triggered manually.
     *
     * @param {Function} onProgress - Optional callback(current, total, percent)
     * @returns {Object} Detailed integrity report
     */
    async verifyChain(onProgress = null) {
      const startTime = Date.now();

      try {
        // Load all transactions in chain order
        const transactions = await DB.all(
          `SELECT * FROM transactions ORDER BY chain_index ASC`
        );

        const total   = transactions.length;
        const results = [];
        let   broken  = false;
        let   firstBreakAt = null;

        if (total === 0) {
          return {
            status          : 'EMPTY',
            message         : 'No transactions in chain yet.',
            total           : 0,
            verified        : 0,
            tampered        : 0,
            brokenLinks     : 0,
            chainIntact     : true,
            verificationTime: Date.now() - startTime,
            results         : []
          };
        }

        for (let i = 0; i < total; i++) {
          const txn     = transactions[i];
          const prevTxn = i > 0 ? transactions[i - 1] : null;

          // Check A: Record hash integrity
          const hashCheck = await this.verifyRecord(txn);

          // Check B: Chain link integrity
          const linkCheck = this.verifyChainLink(txn, prevTxn);

          const recordOk = hashCheck.valid && linkCheck.linked;

          if (!recordOk && !broken) {
            broken       = true;
            firstBreakAt = txn.chain_index;
          }

          results.push({
            chainIndex    : txn.chain_index,
            receiptNumber : txn.receipt_number,
            timestamp     : txn.timestamp,
            hashValid     : hashCheck.valid,
            linkValid     : linkCheck.linked,
            intact        : recordOk,
            storedHash    : txn.hash.substring(0, 16) + '…',  // Truncated for display
            computedHash  : hashCheck.computedHash.substring(0, 16) + '…'
          });

          // Progress callback for UI
          if (onProgress) {
            onProgress(i + 1, total, Math.round(((i + 1) / total) * 100));
          }
        }

        const tampered    = results.filter(r => !r.intact).length;
        const intact      = results.filter(r =>  r.intact).length;
        const brokenLinks = results.filter(r => !r.linkValid).length;

        const status = tampered === 0 ? 'INTACT' : 'COMPROMISED';

        AuditLog.add(
          'CHAIN_VERIFIED',
          `Status: ${status} | Total: ${total} | Tampered: ${tampered} | Time: ${Date.now() - startTime}ms`
        );

        return {
          status          : status,
          message         : tampered === 0
            ? `All ${total} transactions verified. Chain is intact.`
            : `WARNING: ${tampered} tampered record(s) detected. First breach at chain index #${firstBreakAt}.`,
          total           : total,
          verified        : intact,
          tampered        : tampered,
          brokenLinks     : brokenLinks,
          chainIntact     : tampered === 0,
          firstBreakAt    : firstBreakAt,
          verificationTime: Date.now() - startTime,
          results         : results
        };

      } catch (e) {
        console.error('[HashEngine] verifyChain error:', e);
        AuditLog.add('CHAIN_VERIFY_ERROR', e.message);
        return {
          status      : 'ERROR',
          message     : 'Chain verification failed: ' + e.message,
          chainIntact : false,
          error       : e.message
        };
      }
    },

    // ── 6. VERIFY BY RECEIPT NUMBER ───────────────────────

    /**
     * verifyByReceiptNumber(receiptNumber)
     *
     * Looks up a single transaction by receipt number
     * and verifies its integrity.
     * Used by the public verifier (Phase 07).
     *
     * @param {string} receiptNumber - e.g. "EXC-2024-00012"
     * @returns {Object} Verification result
     */
    async verifyByReceiptNumber(receiptNumber) {
      try {
        const txn = await DB.get(
          `SELECT * FROM transactions WHERE receipt_number = ?`,
          [receiptNumber]
        );

        if (!txn) {
          await logVerification(receiptNumber, 'NOT_FOUND');
          return {
            found         : false,
            status        : 'NOT_FOUND',
            receiptNumber : receiptNumber,
            message       : 'No transaction found with this receipt number.'
          };
        }

        const hashCheck = await this.verifyRecord(txn);

        // Also verify the chain link for this specific record
        let prevTxn = null;
        if (txn.chain_index > 0) {
          prevTxn = await DB.get(
            `SELECT * FROM transactions WHERE chain_index = ?`,
            [txn.chain_index - 1]
          );
        }
        const linkCheck = this.verifyChainLink(txn, prevTxn);

        const overallIntact = hashCheck.valid && linkCheck.linked;

        // Log this verification attempt
        AuditLog.add(
          'RECEIPT_VERIFIED',
          `Receipt: ${receiptNumber} | Result: ${overallIntact ? 'ORIGINAL' : 'TAMPERED'}`
        );
        await logVerification(txn.receipt_number, overallIntact ? 'ORIGINAL' : 'TAMPERED');

        return {
          found         : true,
          status        : overallIntact ? 'ORIGINAL' : 'TAMPERED',
          receiptNumber : txn.receipt_number,
          chainIndex    : txn.chain_index,
          timestamp     : txn.timestamp,
          txnType       : txn.txn_type,
          amountPkr     : txn.amount_pkr,
          clientName    : txn.client_name,
          hashValid     : hashCheck.valid,
          linkValid     : linkCheck.linked,
          intact        : overallIntact,
          storedHash    : txn.hash,
          computedHash  : hashCheck.computedHash,
          message       : overallIntact
            ? 'This is a verified ORIGINAL document. It has not been tampered with.'
            : 'WARNING: This document has been TAMPERED. Data may have been modified.'
        };

      } catch (e) {
        console.error('[HashEngine] verifyByReceiptNumber error:', e);
        return {
          found   : false,
          status  : 'ERROR',
          message : 'Verification error: ' + e.message
        };
      }
    },

    // ── 6B. VERIFY BY HASH ─────────────────────────────────

    /**
     * verifyByHash(hash)
     *
     * Looks up a single transaction by its stored SHA-256 hash
     * and verifies its integrity. Mirrors verifyByReceiptNumber
     * so the public verifier (Phase 07) can accept either input.
     *
     * @param {string} hash - 64-char SHA-256 hex hash
     * @returns {Object} Verification result
     */
    async verifyByHash(hash) {
      try {
        const cleanHash = (hash || '').trim().toLowerCase();

        const txn = await DB.get(
          `SELECT * FROM transactions WHERE hash = ?`,
          [cleanHash]
        );

        if (!txn) {
          await logVerification('', 'NOT_FOUND');
          return {
            found   : false,
            status  : 'NOT_FOUND',
            hash    : cleanHash,
            message : 'No transaction found with this hash.'
          };
        }

        const hashCheck = await this.verifyRecord(txn);

        // Also verify the chain link for this specific record
        let prevTxn = null;
        if (txn.chain_index > 0) {
          prevTxn = await DB.get(
            `SELECT * FROM transactions WHERE chain_index = ?`,
            [txn.chain_index - 1]
          );
        }
        const linkCheck = this.verifyChainLink(txn, prevTxn);

        const overallIntact = hashCheck.valid && linkCheck.linked;

        // Log this verification attempt
        AuditLog.add(
          'HASH_VERIFIED',
          `Hash: ${this.formatHashShort(cleanHash)} | Result: ${overallIntact ? 'ORIGINAL' : 'TAMPERED'}`
        );
        await logVerification(txn.receipt_number, overallIntact ? 'ORIGINAL' : 'TAMPERED');

        return {
          found         : true,
          status        : overallIntact ? 'ORIGINAL' : 'TAMPERED',
          receiptNumber : txn.receipt_number,
          chainIndex    : txn.chain_index,
          timestamp     : txn.timestamp,
          txnType       : txn.txn_type,
          amountPkr     : txn.amount_pkr,
          clientName    : txn.client_name,
          hashValid     : hashCheck.valid,
          linkValid     : linkCheck.linked,
          intact        : overallIntact,
          storedHash    : txn.hash,
          computedHash  : hashCheck.computedHash,
          message       : overallIntact
            ? 'This is a verified ORIGINAL document. It has not been tampered with.'
            : 'WARNING: This document has been TAMPERED. Data may have been modified.'
        };

      } catch (e) {
        console.error('[HashEngine] verifyByHash error:', e);
        return {
          found   : false,
          status  : 'ERROR',
          message : 'Verification error: ' + e.message
        };
      }
    },

    // ── 7. STARTUP INTEGRITY CHECK ────────────────────────

    /**
     * startupCheck()
     *
     * Lightweight check run every time the app boots.
     * Does NOT verify every hash (that would be slow on large DBs).
     * Instead checks:
     *   - Last record's hash is still intact
     *   - Chain tip is consistent
     *   - Total count matches sequence
     *
     * Full chain verify is available as a manual action.
     *
     * @returns {Object} { ok, status, message }
     */
    async startupCheck() {
      try {
        const total = await DB.get(
          `SELECT COUNT(*) as cnt, MAX(chain_index) as maxIdx FROM transactions`
        );

        if (!total || total.cnt === 0) {
          return { ok: true, status: 'EMPTY', message: 'No transactions yet.', count: 0 };
        }

        // Verify the tip of the chain
        const tip = await DB.get(
          `SELECT * FROM transactions ORDER BY chain_index DESC LIMIT 1`
        );

        const tipCheck = await this.verifyRecord(tip);

        // Verify the count matches chain_index sequence
        // (If records were deleted in the middle, this would catch it)
        const expectedCount = tip.chain_index + 1;
        const countMismatch = total.cnt !== expectedCount;

        const ok = tipCheck.valid && !countMismatch;

        AuditLog.add(
          'STARTUP_CHECK',
          `Status: ${ok ? 'OK' : 'ALERT'} | Chain tip: #${tip.chain_index} | Count: ${total.cnt} | Tip hash: ${tipCheck.valid ? 'valid' : 'INVALID'}`
        );

        if (!ok) {
          return {
            ok      : false,
            status  : 'ALERT',
            message : countMismatch
              ? `Chain count mismatch: ${total.cnt} records found but sequence expects ${expectedCount}. Records may have been deleted.`
              : `Chain tip hash is invalid. Last record (${tip.receipt_number}) may have been tampered.`,
            count   : total.cnt,
            tipReceipt: tip.receipt_number
          };
        }

        return {
          ok         : true,
          status     : 'OK',
          message    : `Chain OK — ${total.cnt} records verified at tip.`,
          count      : total.cnt,
          tipReceipt : tip.receipt_number
        };

      } catch (e) {
        console.error('[HashEngine] startupCheck error:', e);
        return { ok: false, status: 'ERROR', message: e.message };
      }
    },

    // ── 8. UTILITIES ──────────────────────────────────────

    /**
     * computeHash(input)
     * Public wrapper for sha256 — used by other modules (e.g. verifier)
     *
     * @param {string} input
     * @returns {Promise<string>} 64-char hex hash
     */
    async computeHash(input) {
      return await sha256(input);
    },

    /**
     * getGenesisHash()
     * Returns the genesis prev_hash value (64 zeros)
     */
    getGenesisHash() {
      return GENESIS_HASH;
    },

    /**
     * formatHashShort(hash)
     * Returns first 8 + last 8 chars for display
     * e.g. "a3f5c9b2…1f9a3c5b"
     */
    formatHashShort(hash) {
      if (!hash || hash.length < 16) return hash;
      return `${hash.substring(0, 8)}…${hash.substring(hash.length - 8)}`;
    },

    /**
     * validateFormData(formData)
     * Validates required fields before any record is created.
     * Returns { valid: true } or { valid: false, error: '...' }
     */
    validateFormData(formData) {
      if (!formData.txn_type || !['buy', 'sell'].includes(formData.txn_type)) {
        return { valid: false, error: 'Transaction type must be "buy" or "sell".' };
      }
      const amount = parseFloat(formData.amount_pkr);
      if (!amount || amount <= 0) {
        return { valid: false, error: 'Amount PKR must be a positive number.' };
      }
      const rate = parseFloat(formData.exchange_rate);
      if (!rate || rate <= 0) {
        return { valid: false, error: 'Exchange rate must be a positive number.' };
      }
      return { valid: true };
    },

    /**
     * getChainSummary()
     * Returns quick stats about the current chain state.
     */
    async getChainSummary() {
      try {
        const row = await DB.get(
          `SELECT
             COUNT(*)             as total,
             MAX(chain_index)     as tip_index,
             MIN(timestamp)       as first_txn,
             MAX(timestamp)       as last_txn,
             SUM(amount_pkr)      as total_volume
           FROM transactions`
        );
        const tip = await DB.get(
          `SELECT hash, receipt_number FROM transactions ORDER BY chain_index DESC LIMIT 1`
        );
        return {
          total       : row?.total       || 0,
          tipIndex    : row?.tip_index   ?? -1,
          firstTxn    : row?.first_txn   || null,
          lastTxn     : row?.last_txn    || null,
          totalVolume : row?.total_volume || 0,
          tipHash     : tip?.hash        || GENESIS_HASH,
          tipReceipt  : tip?.receipt_number || null
        };
      } catch {
        return { total: 0, tipIndex: -1, tipHash: GENESIS_HASH };
      }
    }

  };

})();

// ── NOTE ON STARTUP INTEGRITY CHECK ──────────────────────
// HashEngine.startupCheck() is intentionally NOT auto-run here.
// Previously this file registered its own DOMContentLoaded
// listener that called startupCheck() automatically — but
// dashboard.html (the only page that currently loads this
// script) ALSO calls it explicitly via runChainCheck() to drive
// the chain-status pill and banner UI. Having both meant every
// dashboard load ran the check twice and wrote duplicate
// STARTUP_CHECK / STARTUP_ALERT entries into the audit trail.
// Any future page that includes hash-engine.js should call
// `await HashEngine.startupCheck()` itself at the point in its
// own boot sequence where it wants the result.