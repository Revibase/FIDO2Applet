/*
 * openjavacard-ndef: JavaCard applet implementing an NDEF tag
 * Copyright (C) 2015-2018 Ingo Albrecht <copyright@promovicz.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package org.openjavacard.ndef.stub;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;


/**
 * NDEF Type 4 applet that signs URLs with its own AES-protected EC key.
 *
 * <p>The base URL is configured at install time via the application data (AD)
 * install parameter — the AD bytes are the URL string directly.
 *
 * <p>FIDO2 pushes the credential's private key and compressed public key once
 * during {@code makeCredential} (via {@link NdefKeyStore}). The pushed private
 * key is stored AES-256-CBC encrypted under a randomly-generated wrapping key.
 * Note this is <em>logical</em> protection only, mirroring the FIDO2 applet's
 * {@code lowSecurityWrappingKey}: the wrapping key ({@link #wrappingKeySpace})
 * lives in plaintext in EEPROM alongside the ciphertext, so an attacker who can
 * dump EEPROM recovers the private key. It defends against logical read paths,
 * not physical/fault extraction. After provisioning this applet is fully
 * self-contained: on the first NDEF E104 data read it decrypts the key into
 * CLEAR_ON_DESELECT transient memory, signs a fresh counter+nonce, encodes the
 * URL, and clears the plaintext key — no runtime call to the FIDO2 applet is
 * ever needed. Subsequent reads in the same session return the cached payload.
 *
 * <p>If no key has been pushed yet the applet serves a static placeholder URL.
 */
public final class NdefApplet extends Applet implements NdefKeyStore {

    /* Instructions */
    private static final byte INS_SELECT        = ISO7816.INS_SELECT;
    private static final byte INS_READ_BINARY   = (byte) 0xB0;
    private static final byte INS_UPDATE_BINARY = (byte) 0xD6;

    /* File IDs */
    private static final short FILEID_NONE              = (short) 0x0000;
    private static final short FILEID_NDEF_CAPABILITIES = (short) 0xE103;
    private static final short FILEID_NDEF_DATA         = (short) 0xE104;

    /* SELECT parameters */
    private static final byte SELECT_P1_BY_FILEID     = (byte) 0x00;
    private static final byte SELECT_P2_FIRST_OR_ONLY = (byte) 0x0C;

    /** Max READ BINARY Le; keep small for physical JCOP (6700 on large Le is common). */
    private static final short NDEF_MAX_READ             = 32;
    private static final short NDEF_MAX_WRITE            = 32;
    private static final short NDEF_DATA_MAX             = (short) 320;

    /** Maximum base URL length accepted at install time. */
    private static final short MAX_URL_LEN               = 96;

    /** Fixed query suffix in {@link #encodeSignedNdefUriFile} (?pk=&c=&n=&s= + b64). */
    private static final short SIGNED_URI_QUERY_OVERHEAD = (short) 154;
    /** Worst-case decimal digits for uint32 counter in signed URL. */
    private static final short MAX_COUNTER_DECIMAL_DIGITS = (short) 10;
    /** Type 4 file prefix: 2-byte NLEN + 4-byte NDEF record header + URI prefix byte. */
    private static final short NDEF_TYPE4_FILE_PREFIX      = (short) 7;
    /** Max URI body after scheme strip (NDEF record payload limit 255 bytes). */
    private static final short MAX_NDEF_URI_BODY         = (short) (
            255 - 1 - SIGNED_URI_QUERY_OVERHEAD - MAX_COUNTER_DECIMAL_DIGITS);

    /** AES block / IV length. */
    private static final short AES_BLOCK_LEN             = 16;

    /** HMAC-SHA256 truncation length for stored key integrity. */
    private static final short KEY_MAC_LEN               = 16;

    /** storedEncryptedKey (48) + storedPubKey (33). */
    private static final short KEY_BLOB_LEN              = 81;

    /** FIDO2 applet AID authorized to push keys via {@link NdefKeyStore}. */
    private static final byte[] FIDO_PARTNER_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
    };

    // ---- Signing constants ----

    private static final short NONCE_LEN       = 8;
    private static final short RAW_SIG_LEN     = 64;
    private static final short DER_SIG_MAX_LEN = 80;

    // Offsets inside sigScratch
    private static final short SCR_COUNTER    = 0;    // 4 bytes  big-endian counter
    private static final short SCR_NONCE      = 4;    // 8 bytes  random nonce
    private static final short SCR_SIGNMSG    = 12;   // 12 bytes counter||nonce (input to sign)
    private static final short SCR_DER_SIG    = 24;   // 80 bytes DER signature output
    private static final short SCR_RAW_SIG    = 104;  // 64 bytes normalised raw sig
    private static final short SCR_DIV        = 168;  // 8 bytes  scratch for decimal division
    private static final short SCR_DECIMAL    = 176;  // 11 bytes max uint32 decimal digits
    private static final short SCR_PRIVKEY    = 187;  // 32 bytes decrypted private key (cleared after use)
    private static final short SCR_SIZE       = 219;

    /** CLEAR_ON_DESELECT scratch for encrypt-on-first-read and HMAC (NDEF selected only). */
    private static final short COMM_ENC_IV    = 0;
    private static final short COMM_ENC_CT    = 16;
    private static final short COMM_HMAC_MSG  = 64;
    private static final short COMM_HMAC_OUT  = 0;
    private static final short COMM_SCR_SIZE  = 160;

    // P-256 / secp256r1 curve parameters
    private static final byte[] P256_P = {
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff
    };
    private static final byte[] P256_A = {
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfc
    };
    private static final byte[] P256_B = {
            0x5a,(byte)0xc6,0x35,(byte)0xd8,(byte)0xaa,0x3a,(byte)0x93,(byte)0xe7,
            (byte)0xb3,(byte)0xeb,(byte)0xbd,0x55,0x76,(byte)0x98,(byte)0x86,(byte)0xbc,
            0x65,0x1d,0x06,(byte)0xb0,(byte)0xcc,0x53,(byte)0xb0,(byte)0xf6,
            0x3b,(byte)0xce,0x3c,0x3e,0x27,(byte)0xd2,0x60,0x4b
    };
    private static final byte[] P256_G = {
            0x04,
            0x6b,0x17,(byte)0xd1,(byte)0xf2,(byte)0xe1,0x2c,0x42,0x47,
            (byte)0xf8,(byte)0xbc,(byte)0xe6,(byte)0xe5,0x63,(byte)0xa4,0x40,(byte)0xf2,
            0x77,0x03,0x7d,(byte)0x81,0x2d,(byte)0xeb,0x33,(byte)0xa0,
            (byte)0xf4,(byte)0xa1,0x39,0x45,(byte)0xd8,(byte)0x98,(byte)0xc2,(byte)0x96,
            0x4f,(byte)0xe3,0x42,(byte)0xe2,(byte)0xfe,0x1a,0x7f,(byte)0x9b,
            (byte)0x8e,(byte)0xe7,(byte)0xeb,0x4a,0x7c,0x0f,(byte)0x9e,0x16,
            0x2b,(byte)0xce,0x33,0x57,0x6b,0x31,0x5e,(byte)0xce,
            (byte)0xcb,(byte)0xb6,0x40,0x68,0x37,(byte)0xbf,0x51,(byte)0xf5
    };
    private static final byte[] P256_N = {
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,0x00,0x00,0x00,0x00,
            (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
            (byte)0xbc,(byte)0xe6,(byte)0xfa,(byte)0xad,(byte)0xa7,0x17,(byte)0x9e,(byte)0x84,
            (byte)0xf3,(byte)0xb9,(byte)0xca,(byte)0xc2,(byte)0xfc,0x63,0x25,0x51
    };
    private static final byte P256_H = 0x01;

    private static final byte[] B64URL_ALPHABET = {
            'A','B','C','D','E','F','G','H','I','J','K','L','M',
            'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m',
            'n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9','-','_'
    };

    /** Placeholder URI body after {@code https://} prefix (prefix code 0x04). */
    private static final byte[] PLACEHOLDER_URI_BODY = {
            'n', 'o', 't', '-', 'p', 'r', 'o', 'v', 'i', 's', 'i', 'o', 'n', 'e', 'd'
    };

    /**
     * Static capability container (ROM); no EEPROM allocation or runtime writes.
     * Layout for {@link #NDEF_DATA_MAX} (320): mapping 0x20, MLE/MLC 32, E104 size 0x0140.
     */
    private static final byte[] CAPS_FILE = {
            0x00, 0x0F, 0x20, 0x00, 0x20, 0x00, 0x20, 0x04, 0x06,
            (byte) 0xE1, 0x04, 0x01, 0x40, 0x00, (byte) 0xFF
    };

    /** Transient staging for Shareable key push: priv(32) || pub(33). */
    private static final short PENDING_PRIV_OFF = 0;
    private static final short PENDING_PUB_OFF  = NdefKeyStore.PRIV_KEY_LEN;
    private static final short PENDING_KEY_LEN  = (short) (NdefKeyStore.PRIV_KEY_LEN + NdefKeyStore.PUB_KEY_LEN);

    // ---- Transient state (instance — not static; static transient breaks on some JCOP) ----

    private short[] vars;
    private static final byte VAR_SELECTED_FILE = (byte) 0;
    private static final byte VAR_DATA_LEN      = (byte) 1;
    private static final byte VAR_PAYLOAD_READY = (byte) 2;
    private static final short NUM_VARS         = (short) 3;

    /** Transient Type 4 data file (repopulated on every applet SELECT). */
    private byte[] dataBuffer;

    /** Scratch for signing (CLEAR_ON_DESELECT). */
    private byte[] sigScratch;

    /** Scratch for key encryption and HMAC at commit time (CLEAR_ON_DESELECT). */
    private byte[] commitScratch;

    /**
     * Pushed key bytes awaiting encrypt-on-first-NDEF-use.
     * CLEAR_ON_RESET: must survive FIDO deselect between makeCredential push and first NDEF read.
     */
    private byte[] pendingKeyStaging;

    /**
     * Non-zero after {@link #commit()} until {@link #encryptPendingKey()} completes.
     * CLEAR_ON_RESET: paired with {@link #pendingKeyStaging} across applet deselect.
     */
    private byte[] pendingPushReady;

    // ---- Persistent AES key wrapping (EEPROM) ----

    /** 32-byte AES-256 wrapping key material, randomly generated at install time. */
    private final byte[] wrappingKeySpace;
    /** AES key object backed by wrappingKeySpace. */
    private final AESKey wrappingKey;
    /** AES-CBC cipher for encrypting the pushed private key. */
    private final Cipher symmetricWrapper;
    /** AES-CBC cipher for decrypting the stored private key before signing. */
    private final Cipher symmetricUnwrapper;

    // ---- Persistent signing fields (EEPROM) ----

    /**
     * 48-byte encrypted private key: IV (16 bytes) || AES-256-CBC ciphertext (32 bytes).
     * Valid when {@link #keyValid}[0] is non-zero.
     */
    private final byte[] storedEncryptedKey;
    /** 33-byte compressed SEC-1 public key pushed by FIDO2. */
    private final byte[] storedPubKey;
    /** 16-byte HMAC integrity tag over {@link #storedEncryptedKey} || {@link #storedPubKey}. */
    private final byte[] storedKeyMac;
    /** 32-byte key for {@link #storedKeyMac} generation. */
    private final byte[] keyVerificationKey;
    /** Base URL bytes configured at install time. */
    private final byte[] storedBaseUrl;
    /** 2-byte big-endian length of valid bytes in storedBaseUrl. */
    private final byte[] storedUrlLen;
    /** Wear-leveled monotonic counter; batched EEPROM writes on URL generation. */
    private final SigOpCounter sigCounter;
    /** 1-byte flag; non-zero once the encrypted key is committed and ready to use. */
    private final byte[] keyValid;

    // ---- Crypto objects ----

    private final ECPrivateKey signingKey;
    private final Signature    ecSig;
    private final RandomData   rng;
    private final MessageDigest sha256;

    // -----------------------------------------------------------------------

    public static void install(byte[] buf, short off, byte len) {
        short offAD = off;
        byte lenAD = len;

        // GlobalPlatformPro --params passes raw application data.
        // jcardsim passes the full JavaCard install buffer (AID + CI + AD TLVs).
        if (len > 0) {
            short pos = off;
            byte lenAID = buf[pos++];
            if (lenAID >= 5 && lenAID <= 16) {
                short endAID = (short) (pos + lenAID);
                if (endAID < (short) (off + len)) {
                    byte lenCI = buf[endAID];
                    short endCI = (short) (endAID + 1 + (lenCI & 0xFF));
                    if (endCI < (short) (off + len)) {
                        byte lenADCheck = buf[endCI];
                        short endAD = (short) (endCI + 1 + (lenADCheck & 0xFF));
                        if (endAD == (short) (off + len)) {
                            offAD = (short) (endCI + 1);
                            lenAD = lenADCheck;
                        }
                    }
                }
            }
        }

        // GlobalPlatformPro wraps --params in a C9 tag; strip it when present.
        if (lenAD >= 2 && buf[offAD] == (byte) 0xC9) {
            byte innerLen = buf[(short) (offAD + 1)];
            if ((short) (2 + (innerLen & 0xFF)) == (lenAD & 0xFF)) {
                offAD = (short) (offAD + 2);
                lenAD = innerLen;
            }
        }

        NdefApplet applet = new NdefApplet(buf, offAD, lenAD);
        applet.register();
    }

    protected NdefApplet(byte[] buf, short off, byte len) {
        vars       = JCSystem.makeTransientShortArray(NUM_VARS, JCSystem.CLEAR_ON_DESELECT);
        dataBuffer = JCSystem.makeTransientByteArray(NDEF_DATA_MAX, JCSystem.CLEAR_ON_DESELECT);
        sigScratch = JCSystem.makeTransientByteArray(SCR_SIZE, JCSystem.CLEAR_ON_DESELECT);
        commitScratch = JCSystem.makeTransientByteArray(COMM_SCR_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pendingKeyStaging = JCSystem.makeTransientByteArray(PENDING_KEY_LEN, JCSystem.CLEAR_ON_RESET);
        pendingPushReady  = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);

        // EEPROM key storage
        wrappingKeySpace     = new byte[32];
        storedEncryptedKey   = new byte[(short)(AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN)]; // 48
        storedPubKey         = new byte[NdefKeyStore.PUB_KEY_LEN];
        storedKeyMac         = new byte[KEY_MAC_LEN];
        keyVerificationKey   = new byte[32];
        storedBaseUrl        = new byte[MAX_URL_LEN];
        storedUrlLen         = new byte[2];
        sigCounter           = new SigOpCounter();
        keyValid             = new byte[1];

        // AES wrapping setup
        wrappingKey        = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        symmetricWrapper   = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        symmetricUnwrapper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // EC signing setup. Prefer a transient (RAM) private key so that the per-tap
        // curve-param load, setS, and clearKey do not wear EEPROM; fall back to a
        // flash-resident key only on cards that lack transient EC key support.
        signingKey = buildSigningKey();
        ecSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        rng   = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Generate a random AES-256 wrapping key at install time
        rng.generateData(wrappingKeySpace, (short) 0, (short) 32);
        wrappingKey.setKey(wrappingKeySpace, (short) 0);
        rng.generateData(keyVerificationKey, (short) 0, (short) 32);

        // Parse install params: AD bytes are the base URL (optional; empty = no URL, serve placeholder)
        if (len > MAX_URL_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (len > 0) {
            Util.arrayCopyNonAtomic(buf, off, storedBaseUrl, (short) 0, len);
            Util.setShort(storedUrlLen, (short) 0, len);
            final short schemeSkip = schemePrefixSkip(storedBaseUrl, len);
            if (!signedUrlFits(len, schemeSkip)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
    }

    // -----------------------------------------------------------------------
    // NdefKeyStore implementation (called by FIDO2 while FIDO2 is selected)
    // -----------------------------------------------------------------------

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (parameter != NdefKeyStore.SERVICE_ID) {
            return null;
        }
        if (clientAID == null
                || !clientAID.partialEquals(FIDO_PARTNER_AID, (short) 0, (byte) FIDO_PARTNER_AID.length)) {
            return null;
        }
        return this;
    }

    public void setPrivKeyByte(short offset, byte value) {
        if (keyValid[0] != 0 || pendingPushReady[0] != 0) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        if (offset >= 0 && offset < NdefKeyStore.PRIV_KEY_LEN) {
            pendingKeyStaging[(short) (PENDING_PRIV_OFF + offset)] = value;
        }
    }

    public void setPubKeyByte(short offset, byte value) {
        if (keyValid[0] != 0 || pendingPushReady[0] != 0) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        if (offset >= 0 && offset < NdefKeyStore.PUB_KEY_LEN) {
            pendingKeyStaging[(short) (PENDING_PUB_OFF + offset)] = value;
        }
    }

    /**
     * Marks pushed key material ready in transient staging. Encryption into EEPROM is
     * deferred to the first NDEF SELECT/READ while this applet is selected — AES on
     * physical cards requires the NDEF applet context.
     */
    public void commit() {
        if (keyValid[0] != 0 || pendingPushReady[0] != 0) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        pendingPushReady[0] = 1;
    }

    // -----------------------------------------------------------------------
    // Key encryption / decryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts transient staged key material into {@link #storedEncryptedKey}, stores an
     * integrity MAC, and clears plaintext staging atomically (single EEPROM transaction).
     */
    private void encryptPendingKey() {
        if (keyValid[0] != 0) {
            return;
        }
        if (pendingPushReady[0] == 0) {
            return;
        }
        rng.generateData(commitScratch, COMM_ENC_IV, AES_BLOCK_LEN);
        symmetricWrapper.init(wrappingKey, Cipher.MODE_ENCRYPT,
                commitScratch, COMM_ENC_IV, AES_BLOCK_LEN);
        symmetricWrapper.doFinal(pendingKeyStaging, PENDING_PRIV_OFF, NdefKeyStore.PRIV_KEY_LEN,
                commitScratch, COMM_ENC_CT);

        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            Util.arrayCopyNonAtomic(commitScratch, COMM_ENC_IV,
                    storedEncryptedKey, (short) 0, (short) (AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN));
            Util.arrayCopyNonAtomic(pendingKeyStaging, PENDING_PUB_OFF,
                    storedPubKey, (short) 0, NdefKeyStore.PUB_KEY_LEN);
            computeAndStoreKeyMac();
            keyValid[0] = 1;
            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }
        Util.arrayFillNonAtomic(pendingKeyStaging, (short) 0, PENDING_KEY_LEN, (byte) 0);
        pendingPushReady[0] = 0;
    }

    private void computeAndStoreKeyMac() {
        Util.arrayCopyNonAtomic(storedEncryptedKey, (short) 0,
                commitScratch, COMM_HMAC_MSG, (short) (AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN));
        Util.arrayCopyNonAtomic(storedPubKey, (short) 0,
                commitScratch, (short) (COMM_HMAC_MSG + AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN),
                NdefKeyStore.PUB_KEY_LEN);
        hmacSha256(keyVerificationKey, (short) 0,
                commitScratch, COMM_HMAC_MSG, KEY_BLOB_LEN,
                commitScratch, COMM_HMAC_OUT);
        Util.arrayCopyNonAtomic(commitScratch, COMM_HMAC_OUT, storedKeyMac, (short) 0, KEY_MAC_LEN);
    }

    private boolean verifyStoredKeyMac() {
        Util.arrayCopyNonAtomic(storedEncryptedKey, (short) 0,
                commitScratch, COMM_HMAC_MSG, (short) (AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN));
        Util.arrayCopyNonAtomic(storedPubKey, (short) 0,
                commitScratch, (short) (COMM_HMAC_MSG + AES_BLOCK_LEN + NdefKeyStore.PRIV_KEY_LEN),
                NdefKeyStore.PUB_KEY_LEN);
        hmacSha256(keyVerificationKey, (short) 0,
                commitScratch, COMM_HMAC_MSG, KEY_BLOB_LEN,
                commitScratch, COMM_HMAC_OUT);
        return SecureCompare.eq(commitScratch, COMM_HMAC_OUT, storedKeyMac, (short) 0, KEY_MAC_LEN);
    }

    private void hmacSha256(byte[] keyBuff, short keyOff,
            byte[] content, short contentOff, short contentLen,
            byte[] outputBuff, short outputOff) {
        final short workingFirst = 0;
        final short workingSecond = 32;
        final short workingMessage = 64;

        for (short i = 0; i < 32; i++) {
            commitScratch[(short) (workingFirst + i)] =
                    (byte) (keyBuff[(short) (keyOff + i)] ^ (byte) 0x36);
        }
        Util.arrayFillNonAtomic(commitScratch, workingSecond, (short) 32, (byte) 0x36);
        Util.arrayCopyNonAtomic(content, contentOff,
                commitScratch, workingMessage, contentLen);
        sha256.doFinal(commitScratch, workingFirst, (short) (64 + contentLen),
                commitScratch, workingMessage);

        for (short i = 0; i < 32; i++) {
            commitScratch[(short) (workingFirst + i)] =
                    (byte) (keyBuff[(short) (keyOff + i)] ^ (byte) 0x5c);
        }
        Util.arrayFillNonAtomic(commitScratch, workingSecond, (short) 32, (byte) 0x5c);
        sha256.doFinal(commitScratch, workingFirst, (short) 96, outputBuff, outputOff);
    }

    /**
     * Decrypts {@link #storedEncryptedKey} into {@code sigScratch[SCR_PRIVKEY..SCR_PRIVKEY+31]}.
     * The caller must call {@code signingKey.clearKey()} and zero SCR_PRIVKEY after use.
     */
    private void decryptKeyIntoScratch() {
        symmetricUnwrapper.init(wrappingKey, Cipher.MODE_DECRYPT,
                storedEncryptedKey, (short) 0, AES_BLOCK_LEN);
        symmetricUnwrapper.doFinal(storedEncryptedKey, AES_BLOCK_LEN, NdefKeyStore.PRIV_KEY_LEN,
                sigScratch, SCR_PRIVKEY);
    }

    // -----------------------------------------------------------------------
    // URL building (called while NDEF is selected — no FIDO2 contact needed)
    // -----------------------------------------------------------------------

    /**
     * Builds the EC private key object, preferring transient (RAM) storage so that the
     * per-tap {@link #loadSigningKey} / {@code setS} / {@code clearKey} cycle does not
     * write EEPROM. Falls back through CLEAR_ON_RESET to flash-resident on cards that do
     * not support transient EC keys.
     */
    private static ECPrivateKey buildSigningKey() {
        try {
            return (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            // unsupported; try next
        }
        try {
            return (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            // unsupported; fall back to flash
        }
        return (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }

    /**
     * Loads P-256 curve parameters and the decrypted private key from
     * {@code sigScratch[SCR_PRIVKEY]} into {@link #signingKey}.
     */
    private void loadSigningKey() {
        ECKey k = (ECKey) signingKey;
        k.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        k.setA(P256_A,       (short) 0, (short) P256_A.length);
        k.setB(P256_B,       (short) 0, (short) P256_B.length);
        k.setG(P256_G,       (short) 0, (short) P256_G.length);
        k.setR(P256_N,       (short) 0, (short) P256_N.length);
        k.setK(P256_H);
        signingKey.setS(sigScratch, SCR_PRIVKEY, NdefKeyStore.PRIV_KEY_LEN);
    }

    /**
     * Generates a fresh signed NDEF URL and stores it in {@link #dataBuffer}.
     * Crypto or encoding failures propagate as ISO status words (not placeholder).
     */
    private void buildSignedNdefUrl() {
        if (pendingPushReady[0] != 0) {
            encryptPendingKey();
        }
        if (keyValid[0] == 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (!verifyStoredKeyMac()) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Transactional so a tear during the ~1-in-256 byte-rollover cannot corrupt
        // the counter (consistent with the transaction used by encryptPendingKey above).
        if (!sigCounter.increment((short) 1)) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        sigCounter.pack(sigScratch, SCR_COUNTER);
        rng.generateData(sigScratch, SCR_NONCE, NONCE_LEN);
        Util.arrayCopyNonAtomic(sigScratch, SCR_COUNTER, sigScratch, SCR_SIGNMSG, (short) 12);

        // Decrypt private key into CLEAR_ON_DESELECT scratch
        decryptKeyIntoScratch();
        loadSigningKey();
        ecSig.init(signingKey, Signature.MODE_SIGN);
        short derLen = ecSig.sign(sigScratch, SCR_SIGNMSG, (short) 12, sigScratch, SCR_DER_SIG);
        signingKey.clearKey();
        // Clear decrypted private key from transient memory immediately after signing
        Util.arrayFillNonAtomic(sigScratch, SCR_PRIVKEY, NdefKeyStore.PRIV_KEY_LEN, (byte) 0);

        normalizeDerSigToRaw64(sigScratch, SCR_DER_SIG, derLen, sigScratch, SCR_RAW_SIG);

        short fileLen = encodeSignedNdefUriFile(
                storedPubKey,  (short) 0,
                sigScratch,    SCR_COUNTER,
                sigScratch,    SCR_NONCE,
                sigScratch,    SCR_RAW_SIG,
                dataBuffer,    (short) 0,
                sigScratch,    SCR_DIV);

        vars[VAR_DATA_LEN] = fileLen;
    }

    private void servePlaceholder() {
        vars[VAR_DATA_LEN] = encodeUriRecord(
                PLACEHOLDER_URI_BODY, (short) 0, (short) PLACEHOLDER_URI_BODY.length,
                (byte) 0x04, dataBuffer, (short) 0);
    }

    // -----------------------------------------------------------------------
    // URL encoding helpers
    // -----------------------------------------------------------------------

    private short skipNdefUriSchemePrefix() {
        return schemePrefixSkip(storedBaseUrl, Util.getShort(storedUrlLen, (short) 0));
    }

    private static short schemePrefixSkip(byte[] url, short urlLen) {
        if (urlLen >= 8
                && url[0] == 'h' && url[1] == 't'
                && url[2] == 't' && url[3] == 'p'
                && url[4] == 's' && url[5] == ':'
                && url[6] == '/' && url[7] == '/') {
            return 8;
        }
        if (urlLen >= 7
                && url[0] == 'h' && url[1] == 't'
                && url[2] == 't' && url[3] == 'p'
                && url[4] == ':' && url[5] == '/'
                && url[6] == '/') {
            return 7;
        }
        return 0;
    }

    private static boolean signedUrlFits(short urlLen, short schemeSkip) {
        if (schemeSkip > urlLen) {
            return false;
        }
        final short baseBodyLen = (short) (urlLen - schemeSkip);
        if (baseBodyLen > MAX_NDEF_URI_BODY) {
            return false;
        }
        final short bodyLen = (short) (baseBodyLen + SIGNED_URI_QUERY_OVERHEAD + MAX_COUNTER_DECIMAL_DIGITS);
        final short payloadLen = (short) (1 + bodyLen);
        if (payloadLen > 255) {
            return false;
        }
        final short fileLen = (short) (NDEF_TYPE4_FILE_PREFIX + bodyLen);
        return fileLen <= NDEF_DATA_MAX;
    }

    private static short encodeBase64Url(byte[] in, short inOff, short len, byte[] out, short outOff) {
        short pos = outOff;
        short i = 0;
        while (i < len) {
            final short remaining = (short) (len - i);
            final short b0 = (short) (in[(short) (inOff + i)] & 0xFF);
            if (remaining >= 3) {
                final short b1 = (short) (in[(short) (inOff + i + 1)] & 0xFF);
                final short b2 = (short) (in[(short) (inOff + i + 2)] & 0xFF);
                out[pos++] = B64URL_ALPHABET[(b0 >> 2) & 0x3F];
                out[pos++] = B64URL_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F];
                out[pos++] = B64URL_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F];
                out[pos++] = B64URL_ALPHABET[b2 & 0x3F];
                i = (short) (i + 3);
            } else if (remaining == 2) {
                final short b1 = (short) (in[(short) (inOff + i + 1)] & 0xFF);
                out[pos++] = B64URL_ALPHABET[(b0 >> 2) & 0x3F];
                out[pos++] = B64URL_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F];
                out[pos++] = B64URL_ALPHABET[(b1 << 2) & 0x3F];
                i = (short) (i + 2);
            } else {
                out[pos++] = B64URL_ALPHABET[(b0 >> 2) & 0x3F];
                out[pos++] = B64URL_ALPHABET[(b0 << 4) & 0x3F];
                i = (short) (i + 1);
            }
        }
        return (short) (pos - outOff);
    }

    /**
     * Writes a uint32 big-endian counter as exactly {@link #MAX_COUNTER_DECIMAL_DIGITS}
     * zero-padded decimal ASCII digits (e.g. {@code 0000000042}).
     */
    private static short appendUInt32DecimalPadded(byte[] beCounter, short beOff,
            byte[] scratch, short divOff, byte[] out, short outOff) {
        final short tmpOff = (short) (divOff + 8);
        final short numDigits = appendUInt32Decimal(beCounter, beOff,
                scratch, divOff, scratch, tmpOff);
        for (short i = 0; i < MAX_COUNTER_DECIMAL_DIGITS; i++) {
            out[(short) (outOff + i)] = '0';
        }
        Util.arrayCopyNonAtomic(scratch, tmpOff, out,
                (short) (outOff + MAX_COUNTER_DECIMAL_DIGITS - numDigits), numDigits);
        return MAX_COUNTER_DECIMAL_DIGITS;
    }

    private static short appendUInt32Decimal(byte[] beCounter, short beOff,
            byte[] scratch, short divOff, byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(beCounter, beOff, scratch, divOff, (short) 4);
        if (scratch[divOff] == 0 && scratch[(short)(divOff+1)] == 0
                && scratch[(short)(divOff+2)] == 0 && scratch[(short)(divOff+3)] == 0) {
            out[outOff] = '0';
            return 1;
        }
        short digitPos = (short) (outOff + 10);
        short numDigits = 0;
        while (scratch[divOff] != 0 || scratch[(short)(divOff+1)] != 0
                || scratch[(short)(divOff+2)] != 0 || scratch[(short)(divOff+3)] != 0) {
            short remainder = 0;
            for (short j = divOff; j < (short)(divOff + 4); j++) {
                final short v = (short) ((remainder << 8) | (scratch[j] & 0xFF));
                scratch[j] = (byte) (v / 10);
                remainder  = (short) (v % 10);
            }
            out[--digitPos] = (byte) ('0' + remainder);
            numDigits++;
        }
        Util.arrayCopyNonAtomic(out, digitPos, out, outOff, numDigits);
        return numDigits;
    }

    private static void normalizeDerSigToRaw64(byte[] sig, short sigOff, short sigLen,
            byte[] out, short outOff) {
        if (sigLen >= 8 && sig[sigOff] == 0x30) {
            short pos = (short) (sigOff + 2);
            if (sig[(short)(sigOff + 1)] == (byte) 0x81) {
                pos = (short) (sigOff + 3);
            }
            if (sig[pos++] != 0x02) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            short rLen   = (short) (sig[pos++] & 0xFF);
            short rStart = pos;
            pos = (short) (pos + rLen);
            if (sig[pos++] != 0x02) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            short sLen   = (short) (sig[pos++] & 0xFF);
            short sStart = pos;

            Util.arrayFillNonAtomic(out, outOff, RAW_SIG_LEN, (byte) 0);
            copyDerIntField(sig, rStart, rLen, out, outOff);
            copyDerIntField(sig, sStart, sLen, out, (short) (outOff + 32));
            return;
        }
        if (sigLen == RAW_SIG_LEN) {
            if (sigOff != outOff) {
                Util.arrayCopyNonAtomic(sig, sigOff, out, outOff, RAW_SIG_LEN);
            }
            return;
        }
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    private static void copyDerIntField(byte[] in, short inOff, short inLen,
            byte[] out, short outOff) {
        short srcOff  = inOff;
        short copyLen = inLen;
        if (copyLen > 32) {
            srcOff  = (short) (inOff + (copyLen - 32));
            copyLen = 32;
        }
        Util.arrayCopyNonAtomic(in, srcOff, out, (short) (outOff + (32 - copyLen)), copyLen);
    }

    /** Encodes a single Well-Known URI NDEF record into a Type 4 file (NLEN + record). */
    private static short encodeUriRecord(byte[] uriBody, short bodyOff, short bodyLen,
            byte prefixCode, byte[] out, short outOff) {
        final short payloadLen = (short) (1 + bodyLen);
        if (payloadLen > 255) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        final short ndefMsgLen = (short) (4 + payloadLen);
        final short fileLen    = (short) (2 + ndefMsgLen);
        Util.setShort(out, outOff, ndefMsgLen);
        out[(short) (outOff + 2)] = (byte) 0xD1;
        out[(short) (outOff + 3)] = 0x01;
        out[(short) (outOff + 4)] = (byte) payloadLen;
        out[(short) (outOff + 5)] = 0x55;
        out[(short) (outOff + 6)] = prefixCode;
        Util.arrayCopyNonAtomic(uriBody, bodyOff, out, (short) (outOff + 7), bodyLen);
        return fileLen;
    }

    private short encodeSignedNdefUriFile(
            byte[] compressedPub, short compressedOff,
            byte[] counterBE,     short counterOff,
            byte[] nonce,         short nonceOff,
            byte[] signature,     short sigOff,
            byte[] out,           short outOff,
            byte[] scratch,       short scratchOff) {

        final short urlLen       = Util.getShort(storedUrlLen, (short) 0);
        final short schemeSkip   = skipNdefUriSchemePrefix();
        final byte  prefixCode;
        if (schemeSkip == 8) {
            prefixCode = 0x04;   // NFC Forum URI RTD: https://
        } else if (schemeSkip == 7) {
            prefixCode = 0x03;   // NFC Forum URI RTD: http://
        } else {
            prefixCode = 0x00;   // no scheme abbreviation
        }

        final short baseBodyLen   = (short) (urlLen - schemeSkip);
        final short counterDigits = MAX_COUNTER_DECIMAL_DIGITS;

        final short bodyLen      = (short) (baseBodyLen + SIGNED_URI_QUERY_OVERHEAD + counterDigits);
        final short payloadLen   = (short) (1 + bodyLen);
        if (payloadLen > 255) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        final short ndefMsgLen = (short) (4 + payloadLen);
        final short fileLen    = (short) (2 + ndefMsgLen);
        if ((short) (outOff + fileLen) > (short) out.length) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        Util.setShort(out, outOff, ndefMsgLen);
        out[(short)(outOff + 2)] = (byte) 0xD1;
        out[(short)(outOff + 3)] = 0x01;
        out[(short)(outOff + 4)] = (byte) payloadLen;
        out[(short)(outOff + 5)] = 0x55;
        out[(short)(outOff + 6)] = prefixCode;

        short pos = (short) (outOff + 7);
        pos = Util.arrayCopyNonAtomic(storedBaseUrl, schemeSkip, out, pos, baseBodyLen);
        out[pos++] = '?'; out[pos++] = 'p'; out[pos++] = 'k'; out[pos++] = '=';
        pos = (short) (pos + encodeBase64Url(compressedPub, compressedOff,
                NdefKeyStore.PUB_KEY_LEN, out, pos));
        out[pos++] = '&'; out[pos++] = 'c'; out[pos++] = '=';
        pos = (short) (pos + appendUInt32DecimalPadded(counterBE, counterOff,
                scratch, scratchOff, out, pos));
        out[pos++] = '&'; out[pos++] = 'n'; out[pos++] = '=';
        pos = (short) (pos + encodeBase64Url(nonce, nonceOff, NONCE_LEN, out, pos));
        out[pos++] = '&'; out[pos++] = 's'; out[pos++] = '=';
        pos = (short) (pos + encodeBase64Url(signature, sigOff, RAW_SIG_LEN, out, pos));

        if (pos != (short) (outOff + fileLen)) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        return fileLen;
    }

    // -----------------------------------------------------------------------
    // NDEF file helpers
    // -----------------------------------------------------------------------

    /**
     * Builds or refreshes the NDEF data file (signed URL or placeholder) once per
     * RF session ({@link #VAR_PAYLOAD_READY}).
     */
    private void prepareNdefDataFile() {
        final short urlLen = Util.getShort(storedUrlLen, (short) 0);
        if (urlLen > 0 && (keyValid[0] != 0 || pendingPushReady[0] != 0)) {
            buildSignedNdefUrl();
        } else {
            servePlaceholder();
        }
    }

    private void ensurePayloadReady() {
        if (vars[VAR_PAYLOAD_READY] == 0) {
            prepareNdefDataFile();
            vars[VAR_PAYLOAD_READY] = 1;
        }
    }

    // -----------------------------------------------------------------------
    // APDU processing
    // -----------------------------------------------------------------------

    public final void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (selectingApplet()) {
            vars[VAR_SELECTED_FILE] = FILEID_NONE;
            // Do NOT build the signed payload here: SELECT and capability (E103)
            // probes must not consume a counter value or run an ECDSA sign. The
            // payload is generated lazily on the first E104 data read.
            return;
        }

        if (apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        if (apdu.isISOInterindustryCLA()) {
            if (ins == INS_SELECT) {
                processSelect(apdu);
            } else if (ins == INS_READ_BINARY) {
                processReadBinary(apdu);
            } else if (ins == INS_UPDATE_BINARY) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            } else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private void processSelect(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P1] != SELECT_P1_BY_FILEID) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        final byte p2 = buffer[ISO7816.OFFSET_P2];
        // NFC Forum Type 4 uses P2=0x00; ISO 7816-4 also allows 0x0C.
        if (p2 != (byte) 0x00 && p2 != SELECT_P2_FIRST_OR_ONLY) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        short lc = apdu.setIncomingAndReceive();
        if (lc < 2) {
            lc = apdu.getIncomingLength();
        }
        if (lc < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fileId = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (fileId == FILEID_NDEF_CAPABILITIES || fileId == FILEID_NDEF_DATA) {
            vars[VAR_SELECTED_FILE] = fileId;
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    private void processReadBinary(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short fileId = vars[VAR_SELECTED_FILE];
        short offset  = Util.getShort(buffer, ISO7816.OFFSET_P1);
        // Only an E104 data read needs the dynamic payload. The capability file
        // (E103) is static, so a CC read never triggers signing. ensurePayloadReady
        // is idempotent within a session (VAR_PAYLOAD_READY), so building on the
        // first data read (whatever its offset) is safe and must precede fileLength.
        if (fileId == FILEID_NDEF_DATA) {
            ensurePayloadReady();
        }
        short fileLen = fileLength(fileId);
        byte[] file   = accessFileForRead(fileId);
        if (offset < 0 || offset >= fileLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short remaining = (short) (fileLen - offset);
        short le = apdu.setOutgoingNoChaining();
        if (le == 0 || le > NDEF_MAX_READ) {
            le = NDEF_MAX_READ;
        }
        if (le > remaining) {
            le = remaining;
        }
        if (le <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(file, offset, le);
    }

    private short fileLength(short fileId) {
        if (fileId == FILEID_NDEF_CAPABILITIES) return (short) CAPS_FILE.length;
        if (fileId == FILEID_NDEF_DATA)         return vars[VAR_DATA_LEN];
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    private byte[] accessFileForRead(short fileId) {
        if (fileId == FILEID_NDEF_CAPABILITIES) return CAPS_FILE;
        if (fileId == FILEID_NDEF_DATA)         return dataBuffer;
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return null;
    }
}
