package us.q3q.fido2;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;

/**
 * A single-credential P-256 signing appliance that speaks CTAP2/U2F framing.
 *
 * <p><b>This is intentionally not a full FIDO2/WebAuthn authenticator.</b> It is a
 * deliberately reduced signing token. An auditor should read it with the following
 * security model in mind (see {@code docs/capabilities.md} for the authoritative list):
 *
 * <ul>
 *   <li><b>One credential for the life of the card.</b> The first {@code makeCredential}
 *       ({@code rk:true} required) creates a single P-256 key; every later
 *       {@code makeCredential}, {@code getAssertion}, U2F REGISTER/AUTHENTICATE and NDEF
 *       tap reuses that same key. There is no credential management and no reset.</li>
 *   <li><b>No user verification.</b> No PIN, no biometrics, no on-card presence test.
 *       Possession of the card is the entire authorization: anyone who can send APDUs can
 *       obtain signatures. This is by design.</li>
 *   <li><b>Credential ID = the 33-byte compressed public key.</b> The assertion
 *       {@code user.id} and the NDEF {@code pk} are the same value. The request
 *       {@code user.id}/{@code user.name}/RP ID are accepted but not stored.</li>
 *   <li><b>RP is not enforced.</b> {@code allowList}/{@code excludeList} are ignored; the
 *       card signs over whatever RP ID / clientDataHash the host sends.</li>
 *   <li><b>Attestation:</b> {@code packed} self-attestation by default; switchable to basic
 *       ({@code x5c}) via vendor command {@code 0x46}, gated by install param {@code 0x00}
 *       and only while the signature counter is still zero (before any signing).</li>
 *   <li><b>NDEF companion:</b> the NDEF applet owns a <i>separate</i> key and signs its own URL;
 *       this applet's credential key is never shared with it. The two public keys are bound to
 *       one card server-side at enrollment.</li>
 * </ul>
 *
 * <p><b>Memory discipline (recurring pattern throughout):</b> secrets are held in JavaCard
 * key objects or in transient (RAM) scratch obtained from {@link BufferManager}; the
 * working signing key is a transient copy cleared after every use
 * ({@code ecKeyPair.getPrivate().clearKey()}), and scratch holding a private scalar is
 * zero-filled in a {@code finally} block. Persistent state changes (key creation, counter
 * bumps, attestation load) are wrapped in {@link JCSystem} transactions for tear safety.
 *
 * <p><b>Transport:</b> CTAP CBOR over APDU ({@code CLA 0x80}, {@code INS 0x10}) with
 * extended-APDU support for the large commands; raw U2F uses {@code CLA 0x00}. The APDU
 * entry point is {@link #process(APDU)}.
 */
public final class FIDO2Applet extends Applet implements ExtendedLength {

    /** Reported in getInfo; bump when the wire behavior changes. */
    private static final byte FIRMWARE_VERSION = 0x09;

    // ---- Fixed sizes (P-256 / CTAP wire constants) ----------------------------------

    /** Length of one EC coordinate / the private scalar, in bytes. */
    private static final short KEY_POINT_LENGTH = 32;
    /** External FIDO credential ID length (= compressed secp256r1 public key: 0x02/03 || X). */
    private static final short CREDENTIAL_ID_LEN = 33;
    /** Uncompressed SEC1 public key length (0x04 || X || Y). */
    private static final short PUB_KEY_LENGTH = (short) (2 * KEY_POINT_LENGTH + 1);
    /** SHA-256 output length, used for both the RP-ID hash and the clientDataHash. */
    private static final short RP_HASH_LEN = 32;
    private static final short CLIENT_DATA_HASH_LEN = 32;
    /** Largest request {@code user.id} we accept (it is validated then discarded). */
    private static final short MAX_USER_ID_LENGTH = 64;

    // ---- Install-time configuration (see the install() parameter parser) -------------

    /** Whether vendor command 0x46 may load a basic-attestation cert (install param 0x00). */
    private boolean attestationSwitchingEnabled;
    private short MAX_RAM_SCRATCH_SIZE;
    private short BUFFER_MEM_SIZE;
    private short FLASH_SCRATCH_SIZE;

    // ---- The single resident credential ----------------------------------------------

    /** One-element array holding the sole resident credential (or empty). */
    private ResidentKeyData[] residentKeys;
    /** 0 until the credential is created, then 1 for the life of the card. */
    private short numResidentCredentials;
    /**
     * Working keypair used only as a transient home for the resident scalar during
     * signing (and for fresh key generation). Never the durable copy of the credential:
     * the persistent key lives in {@code residentKeys[0]}. Cleared after every use.
     */
    private KeyPair ecKeyPair;

    // ---- Attestation ------------------------------------------------------------------

    /** Basic-attestation private key, or null for self-attestation (the default). */
    private ECPrivateKey attestationKey;
    /** CBOR-encoded x5c certificate chain, streamed in via command 0x46; null if unset. */
    private byte[] attestationData;
    /** Bytes of {@link #attestationData} received so far (chain load is incremental). */
    private short filledAttestationData;
    /** Authenticator AAGUID; all-zero for self-attestation, set when a cert is loaded. */
    private final byte[] aaguid = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // ---- Shared services and scratch (created once at install) -----------------------

    private final RandomData random;
    private final MessageDigest sha256;
    /** ECDSA-SHA256 signer, re-initialised per operation with the relevant key. */
    private final Signature attester;
    /** Monotonic, wear-leveled 32-bit signature counter (persistent). */
    private final SigOpCounter counter;
    /** Compact in-RAM request/response state (options, chaining offsets, continuation). */
    private final TransientStorage transientStorage;
    /** RAM-first scratch allocator used for all per-request working buffers. */
    private BufferManager bufferManager;
    /** Main request/response staging buffer (RAM if it fits, else flash). */
    private byte[] bufferMem;

    private static boolean isExtendedApdu(APDU apdu) {
        return apdu.getOffsetCdata() == ISO7816.OFFSET_EXT_CDATA;
    }

    private static void sendBuffer(APDU apdu, short len) {
        final short blockPayload = (short) (APDU.getOutBlockSize() - 2);
        if (isExtendedApdu(apdu) && len > blockPayload) {
            apdu.setOutgoingLength(len);
            apdu.sendBytes((short) 0, len);
        } else {
            apdu.setOutgoingAndSend((short) 0, len);
        }
    }

    private static void sendByteArray(APDU apdu, byte[] array, short len) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(array, (short) 0, buffer, (short) 0, len);
        sendBuffer(apdu, len);
    }

    private void sendNoCopy(APDU apdu, short len) {
        bufferManager.clear();
        sendBuffer(apdu, len);
    }

    /**
     * Emits a single CTAP error byte as the response body with SW 0x9000 (CTAP carries its
     * status in the payload, not the status word) and unwinds the current command. Also
     * clears scratch and the working key. Never returns normally.
     */
    private void sendErrorByte(APDU apdu, byte sendByte) {
        transientStorage.clearOutgoingContinuation();
        bufferManager.clear();
        byte[] buffer = apdu.getBuffer();
        buffer[0] = sendByte;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        throwException(ISO7816.SW_NO_ERROR);
    }

    /**
     * Reads the full request body of length {@code lc} into a single contiguous buffer and
     * returns it. Small non-chained requests stay in the APDU buffer; larger or chained
     * requests are assembled into {@link #bufferMem} at the current chaining offset.
     * Over-long input is rejected with {@code REQUEST_TOO_LARGE}; a length mismatch with
     * {@code SW_WRONG_LENGTH}.
     */
    private byte[] fullyReadReq(APDU apdu, short lc, short amtRead, boolean forceBuffering) {
        byte[] buffer = apdu.getBuffer();
        final short chainOff = transientStorage.getChainIncomingReadOffset();
        final boolean extendedAPDU = isExtendedApdu(apdu);
        final boolean packInAPDU = !forceBuffering && (!extendedAPDU
                || (chainOff == 0 && ((short) (buffer.length) < 0 || lc <= (short) (buffer.length - 3))));
        if (packInAPDU) {
            Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), buffer, (short) 0, amtRead);
            while (amtRead < lc) {
                short read = apdu.receiveBytes(amtRead);
                if (read == 0) {
                    throwException(ISO7816.SW_WRONG_LENGTH);
                }
                amtRead += read;
            }
            if (amtRead != lc) {
                throwException(ISO7816.SW_WRONG_LENGTH);
            }
            transientStorage.resetChainIncomingReadOffset();
            return buffer;
        }
        // The write cursor is offset by chainOff (accumulated chained input), so the
        // capacity checks must account for it or a near-full buffer overruns bufferMem.
        if ((short) (chainOff + amtRead) > (short) bufferMem.length) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), bufferMem, chainOff, amtRead);
        short curRead = amtRead;
        while (curRead < lc) {
            short read = apdu.receiveBytes((short) 0);
            if (read == 0) {
                throwException(ISO7816.SW_WRONG_LENGTH);
            }
            if ((short) (curRead + chainOff) > (short) (bufferMem.length - read)) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            Util.arrayCopyNonAtomic(buffer, (short) 0, bufferMem, (short) (curRead + chainOff), read);
            curRead = (short) (curRead + read);
        }
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);
        if (curRead > lc) {
            transientStorage.resetChainIncomingReadOffset();
            throwException(ISO7816.SW_WRONG_LENGTH);
        }
        if (!apdu.isCommandChainingCLA()) {
            transientStorage.resetChainIncomingReadOffset();
        }
        return bufferMem;
    }

    /** U2F authenticate requires a provisioned attestation certificate chain. */
    private boolean isU2fProvisioned() {
        return attestationData != null && filledAttestationData >= attestationData.length;
    }

    /**
     * Parses the {@code options} map, recording {@code rk}/{@code up} into
     * {@link TransientStorage} and rejecting unsupported combinations: {@code uv:true} →
     * {@code UNSUPPORTED_OPTION}; for makeCredential ({@code requireRK}) {@code up:false} →
     * {@code INVALID_OPTION} and a missing {@code rk} → {@code INVALID_OPTION}. Unknown
     * option keys are skipped.
     */
    private short processOptionsMap(APDU apdu, byte[] buffer, short readIdx, short lc, boolean requireRK) {
        short numOptions = getMapEntryCount(apdu, buffer[readIdx++]);
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        for (short j = 0; j < numOptions; j++) {
            if ((buffer[readIdx] & 0xF0) != 0x60) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            short optionStrLen = (short) (buffer[readIdx++] & 0x0F);
            if (optionStrLen == 2 && buffer[readIdx] == 'r' && buffer[(short) (readIdx + 1)] == 'k') {
                readIdx += 2;
                if (buffer[readIdx] == (byte) 0xF5) {
                    transientStorage.setRKOption(true);
                } else if (buffer[readIdx] == (byte) 0xF4) {
                    transientStorage.setRKOption(false);
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                readIdx++;
                continue;
            }
            if (optionStrLen == 2 && buffer[readIdx] == 'u' && buffer[(short) (readIdx + 1)] == 'p') {
                readIdx += 2;
                if (buffer[readIdx] == (byte) 0xF5) {
                    transientStorage.setUPOption(true);
                } else if (buffer[readIdx] == (byte) 0xF4) {
                    if (requireRK) {
                        // up:false is invalid for makeCredential (CTAP2.1; real
                        // platforms send up:true, which is accepted)
                        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
                    }
                    transientStorage.setUPOption(false);
                } else {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                readIdx++;
                continue;
            }
            if (optionStrLen == 2 && buffer[readIdx] == 'u' && buffer[(short) (readIdx + 1)] == 'v') {
                readIdx += 2;
                if (buffer[readIdx] == (byte) 0xF5) {
                    // Built-in user verification is not supported
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_OPTION);
                } else if (buffer[readIdx] != (byte) 0xF4) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                readIdx++;
                continue;
            }
            readIdx += optionStrLen;
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        if (requireRK && !transientStorage.hasRKOption()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
        }
        return readIdx;
    }

    /**
     * Reject a pinUvAuthParam per CTAP2.0: a zero-length value is the platform
     * probing
     * for PIN state (answer: no PIN is set); anything else can never verify because
     * clientPin is unsupported. Always terminates the request.
     */
    private void rejectPinUvAuthParam(APDU apdu, byte[] buffer, short readIdx, short lc) {
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        final short valDef = ub(buffer[readIdx]);
        short paramLen = -1;
        if (valDef >= 0x0040 && valDef <= 0x0057) {
            paramLen = (short) (valDef - 0x0040);
        } else if (valDef == 0x0058) {
            if ((short) (readIdx + 1) >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            paramLen = ub(buffer[(short) (readIdx + 1)]);
        }
        if (paramLen < 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        sendErrorByte(apdu, paramLen == 0 ? FIDOConstants.CTAP2_ERR_PIN_NOT_SET
                : FIDOConstants.CTAP2_ERR_PIN_AUTH_INVALID);
    }

    private short getAuthDataLen(boolean includeAttestedKey) {
        short basicLen = (short) (RP_HASH_LEN + 1 + 4);
        if (!includeAttestedKey) {
            return basicLen;
        }
        return (short) (basicLen + (short) aaguid.length + 2 + CREDENTIAL_ID_LEN
                + CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE.length + KEY_POINT_LENGTH + 3 + KEY_POINT_LENGTH);
    }

    private short writeAD(byte[] outBuf, short writeIdx, short adLen, byte[] rpIdHashBuffer, short rpIdHashOffset,
            byte[] pubKeyBuffer, short pubKeyOffset, byte flags,
            byte[] encodedCredBuffer, short encodedCredOffset) {
        short adAddlBytes = writeADBasic(outBuf, adLen, writeIdx, flags, rpIdHashBuffer, rpIdHashOffset);
        writeIdx += getAuthDataLen(false) + adAddlBytes;
        writeIdx = Util.arrayCopyNonAtomic(aaguid, (short) 0, outBuf, writeIdx, (short) aaguid.length);
        writeIdx = Util.setShort(outBuf, writeIdx, CREDENTIAL_ID_LEN);
        writeIdx = Util.arrayCopyNonAtomic(encodedCredBuffer, encodedCredOffset, outBuf, writeIdx, CREDENTIAL_ID_LEN);
        writeIdx = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE, (short) 0,
                outBuf, writeIdx, (short) CannedCBOR.PUBLIC_KEY_ALG_PREAMBLE.length);
        writeIdx = writePubKey(outBuf, writeIdx, pubKeyBuffer, pubKeyOffset);
        return adAddlBytes;
    }

    /**
     * Loads the resident private scalar into the ephemeral working key and inits
     * {@link #attester}. Persistent resident key is never passed to Signature.
     * Caller must {@code clearKey()} the working key after signing.
     */
    private void loadResidentIntoWorkingAttester(APDU apdu, short rkNum) {
        if (residentKeys[rkNum] == null || !residentKeys[rkNum].hasPrivateKey()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }
        final short scratchHandle = bufferManager.allocate(apdu, KEY_POINT_LENGTH,
                BufferManager.NOT_APDU_BUFFER);
        final byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        try {
            residentKeys[rkNum].getPrivateKey().getS(scratch, scratchOff);
            ECPrivateKey working = (ECPrivateKey) ecKeyPair.getPrivate();
            P256Constants.setCurve(working);
            working.setS(scratch, scratchOff, KEY_POINT_LENGTH);
            attester.init(working, Signature.MODE_SIGN);
        } finally {
            Util.arrayFillNonAtomic(scratch, scratchOff, KEY_POINT_LENGTH, (byte) 0);
            bufferManager.release(apdu, scratchHandle, KEY_POINT_LENGTH);
        }
    }

    /** True when the single resident slot holds an initialized private key. */
    private boolean hasUsableResidentKey() {
        return numResidentCredentials > 0 && residentKeys[0] != null
                && residentKeys[0].hasPrivateKey();
    }

    private void throwException(short swCode) {
        throwException(swCode, true);
    }

    private void throwException(short swCode, boolean clearIteration) {
        if (clearIteration) {
            transientStorage.clearOutgoingContinuation();
        }
        bufferManager.clear();
        ecKeyPair.getPrivate().clearKey();
        ISOException.throwIt(swCode);
    }

    // =====================================================================================
    // Response output and ISO chaining
    //
    // A CTAP response lives in bufferMem (optionally followed by a streamed x5c chain). If
    // it fits the expected Le it is sent in one shot; otherwise it is delivered in chunks,
    // either as native extended-APDU blocks or via ISO GET RESPONSE (0x61XX status words),
    // with the continuation position tracked in transientStorage.
    // =====================================================================================

    /**
     * Sends an assembled CTAP response of {@code outputLen} bytes from {@link #bufferMem},
     * appending the attestation {@code x5c} chain if one was deferred. Sets up response
     * chaining when the payload exceeds what one transfer can carry.
     */
    private void doSendResponse(APDU apdu, short outputLen) {
        bufferManager.clear();
        final boolean x5c = transientStorage.shouldStreamX5CLater();
        final boolean isExtendedAPDU = isExtendedApdu(apdu);
        final short apduBlockSize = (short) (APDU.getOutBlockSize() - 2);
        final short expectedLen = apdu.setOutgoing();
        short totalOutputLen = outputLen;
        if (x5c) {
            totalOutputLen = (short) (totalOutputLen + attestationData.length);
        }
        short amountFitInBuffer = totalOutputLen;
        if (amountFitInBuffer > expectedLen) {
            amountFitInBuffer = expectedLen;
        }
        if (amountFitInBuffer > apduBlockSize) {
            amountFitInBuffer = apduBlockSize;
        }
        short amountFromMem = amountFitInBuffer;
        if (amountFromMem > outputLen) {
            amountFromMem = outputLen;
        }
        if (isExtendedAPDU) {
            apdu.setOutgoingLength(totalOutputLen);
        } else {
            apdu.setOutgoingLength(amountFitInBuffer);
        }
        final byte[] apduBytes = apdu.getBuffer();
        Util.arrayCopyNonAtomic(bufferMem, (short) 0, apduBytes, (short) 0, amountFromMem);
        if (x5c) {
            transientStorage.setStoredVars(outputLen, (byte) -1);
            if (amountFromMem < amountFitInBuffer) {
                short availableForX5C = (short) (amountFitInBuffer - amountFromMem);
                if (availableForX5C > attestationData.length) {
                    availableForX5C = (short) attestationData.length;
                }
                Util.arrayCopyNonAtomic(attestationData, (short) 0, apduBytes, amountFromMem, availableForX5C);
            }
        }
        apdu.sendBytes((short) 0, amountFitInBuffer);
        if (totalOutputLen > amountFitInBuffer) {
            if (isExtendedAPDU) {
                transientStorage.setOutgoingContinuation(amountFitInBuffer,
                        (short) (totalOutputLen - amountFitInBuffer));
                while (!streamOutgoingContinuation(apdu, apduBytes, false))
                    ;
            } else {
                setupChainedResponse(amountFitInBuffer, (short) (totalOutputLen - amountFitInBuffer));
            }
        }
    }

    private boolean streamOutgoingContinuation(APDU apdu, byte[] apduBytes, boolean chaining) {
        if (transientStorage.getOutgoingContinuationRemaining() == 0) {
            return true;
        }
        short outgoingOffset = transientStorage.getOutgoingContinuationOffset();
        short outgoingRemaining = transientStorage.getOutgoingContinuationRemaining();
        final boolean x5c = transientStorage.shouldStreamX5CLater();
        short remainingValidInBufMem = outgoingRemaining;
        short x5cidx = 0;
        if (x5c) {
            remainingValidInBufMem = transientStorage.getStoredIdx();
            if (remainingValidInBufMem > outgoingOffset) {
                remainingValidInBufMem = (short) (remainingValidInBufMem - outgoingOffset);
            } else {
                x5cidx = (short) (outgoingOffset - remainingValidInBufMem);
                remainingValidInBufMem = (short) 0;
                if (x5cidx > attestationData.length) {
                    x5cidx = (short) attestationData.length;
                }
            }
        }
        short chunkSize = (short) (APDU.getOutBlockSize() - 2);
        if (chaining) {
            final short requestedChunkSize = apdu.setOutgoing();
            if (requestedChunkSize < chunkSize) {
                chunkSize = requestedChunkSize;
            }
        }
        final short writeSize = chunkSize <= outgoingRemaining ? chunkSize : outgoingRemaining;
        if (chaining) {
            apdu.setOutgoingLength(writeSize);
        }
        short chunkToWrite = writeSize;
        if (remainingValidInBufMem > 0) {
            short writeFromBufMem = remainingValidInBufMem;
            if (writeFromBufMem > chunkToWrite) {
                writeFromBufMem = chunkToWrite;
            }
            Util.arrayCopyNonAtomic(bufferMem, outgoingOffset, apduBytes, (short) 0, writeFromBufMem);
            chunkToWrite -= writeFromBufMem;
        }
        if (x5c && chunkToWrite > 0) {
            short x5crem = (short) (attestationData.length - x5cidx);
            if (x5crem > chunkToWrite) {
                x5crem = chunkToWrite;
            }
            Util.arrayCopyNonAtomic(attestationData, x5cidx, apduBytes, remainingValidInBufMem, x5crem);
        }
        apdu.sendBytes((short) 0, writeSize);
        outgoingOffset += writeSize;
        outgoingRemaining -= writeSize;
        transientStorage.setOutgoingContinuation(outgoingOffset, outgoingRemaining);
        if (chaining) {
            if (outgoingRemaining >= 256) {
                throwException(ISO7816.SW_BYTES_REMAINING_00, false);
            } else if (outgoingRemaining > 0) {
                throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + outgoingRemaining), false);
            } else {
                transientStorage.clearOutgoingContinuation();
            }
        }
        return false;
    }

    private void handleAppletSelect(APDU apdu) {
        apdu.setIncomingAndReceive();
        if (bufferManager == null) {
            initTransientStorage(apdu);
            short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            final short transientMem = availableMem >= MAX_RAM_SCRATCH_SIZE ? MAX_RAM_SCRATCH_SIZE : availableMem;
            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                bufferManager = new BufferManager(transientMem, FLASH_SCRATCH_SIZE);
                bufferManager.initializeAPDU(apdu);
                ok = true;
            } finally {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        }
        bufferManager.clear();
        if (isU2fProvisioned()) {
            sendByteArray(apdu, CannedCBOR.U2F_V2_RESPONSE, (short) CannedCBOR.U2F_V2_RESPONSE.length);
        } else {
            sendByteArray(apdu, CannedCBOR.FIDO_2_RESPONSE, (short) CannedCBOR.FIDO_2_RESPONSE.length);
        }
    }

    private void initTransientStorage(APDU apdu) {
        if (ecKeyPair.getPrivate().getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
            initCredKey(true);
            P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
            P256Constants.setCurve((ECPublicKey) ecKeyPair.getPublic());
        }
        short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        boolean requestBufferInRam = availableMem >= BUFFER_MEM_SIZE;
        bufferMem = getTempOrFlashByteBuffer(BUFFER_MEM_SIZE, requestBufferInRam);
    }

    /**
     * Handles CTAP {@code authenticatorGetInfo} (0x04). Emits a fixed 7-entry map:
     * versions ({@code FIDO_2_0}, plus {@code U2F_V2} once attestation is provisioned),
     * AAGUID, options ({@code rk:true, up:true}), maxMsgSize, maxCredentialIdLength (33),
     * the ES256 algorithm, and the firmware version. Options deliberately omit {@code uv}
     * and {@code clientPin} so platforms do not attempt UV/PIN setup this token cannot do.
     */
    private void sendAuthInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        final byte mapEntries = 7;
        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) (0xA0 + mapEntries);
        buffer[offset++] = 0x01;
        if (isU2fProvisioned()) {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITH_U2F, (short) 0,
                    buffer, offset, (short) CannedCBOR.VERSIONS_WITH_U2F.length);
        } else {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITHOUT_U2F, (short) 0,
                    buffer, offset, (short) CannedCBOR.VERSIONS_WITHOUT_U2F.length);
        }
        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_LITE_AAGUID, (short) 0,
                buffer, offset, (short) CannedCBOR.AUTH_INFO_LITE_AAGUID.length);
        offset = Util.arrayCopyNonAtomic(aaguid, (short) 0, buffer, offset, (short) aaguid.length);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_LITE_OPTIONS, (short) 0,
                buffer, offset, (short) CannedCBOR.AUTH_INFO_LITE_OPTIONS.length);
        buffer[offset++] = 0x05;
        buffer[offset++] = 0x19;
        offset = Util.setShort(buffer, offset, (short) bufferMem.length);
        buffer[offset++] = 0x08;
        offset = encodeIntTo(buffer, offset, (byte) CREDENTIAL_ID_LEN);
        buffer[offset++] = 0x0A;
        offset = Util.arrayCopyNonAtomic(CannedCBOR.ES256_ALG_TYPE, (short) 0,
                buffer, offset, (short) CannedCBOR.ES256_ALG_TYPE.length);
        buffer[offset++] = 0x0E;
        offset = encodeIntTo(buffer, offset, FIRMWARE_VERSION);
        sendNoCopy(apdu, offset);
    }

    // =====================================================================================
    // CTAP commands: makeCredential, getAssertion, getInfo
    // =====================================================================================

    /**
     * Handles CTAP {@code authenticatorMakeCredential} (0x01).
     *
     * <p>The request is a CBOR map whose integer keys MUST appear in ascending order
     * (canonical CTAP encoding); the parser walks them positionally:
     * <pre>
     *   0x01 clientDataHash   byte string, 32 bytes
     *   0x02 rp               map, {@code id} used for the RP-ID hash (rest ignored)
     *   0x03 user             map, {@code id} length-checked then discarded
     *   0x04 pubKeyCredParams array, MUST offer ES256 (alg -7); others ignored
     *   0x07 options          only {rk:true (required), up:true} accepted
     *   0x08 pinUvAuthParam   always rejected (no clientPin) — see rejectPinUvAuthParam
     * </pre>
     *
     * <p>Behavior: on the first call it generates the sole resident P-256 key; every later
     * call reuses it and returns a fresh attestation over the same key (credential ID = the
     * compressed public key). Emits a {@code packed} attestation object. The key stays in this
     * applet; the NDEF companion signs its own URL with a separate key.
     * {@code buffer[0]} is the command byte, so parsing starts at 1.
     *
     * @param lc     total request length including the command byte
     * @param buffer request buffer ({@link #bufferMem} or the APDU buffer)
     */
    private void makeCredential(APDU apdu, short lc, byte[] buffer) {
        // ---- Parse the four mandatory ordered map keys (0x01..0x04) ----
        short readIdx = 1;
        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        final short numParameters = getMapEntryCount(apdu, buffer[readIdx++]);
        if (numParameters < 4) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] != 0x01) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] == 0x58) {
            if (buffer[readIdx++] != CLIENT_DATA_HASH_LEN) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        short clientDataHashIdx = readIdx;
        readIdx += CLIENT_DATA_HASH_LEN;
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (buffer[readIdx++] != 0x02) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        readIdx = readRpIdMap(apdu, buffer, readIdx, lc);
        final short rpIdIdx = transientStorage.getStoredIdx();
        short rpIdLen = transientStorage.getStoredLen();
        if (buffer[readIdx++] != 0x03) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        readIdx = readUserMap(apdu, buffer, readIdx, lc);
        // getStoredLen() is a signed byte; compare unsigned so user.id lengths 128-255
        // are still rejected (a signed comparison would treat them as negative).
        final short userIdLen = ub(transientStorage.getStoredLen());
        if (userIdLen > MAX_USER_ID_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }
        if (buffer[readIdx++] != 0x04) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        final byte pubKeyCredParamsType = buffer[readIdx++];
        if ((pubKeyCredParamsType & 0xF0) != 0x80) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        readIdx = requireEs256PubKeyParams(apdu, buffer, readIdx, lc, pubKeyCredParamsType);
        defaultOptions();
        byte lastMapKey = 0x04;
        for (short i = 4; i < numParameters; i++) {
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (buffer[readIdx] <= lastMapKey) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            lastMapKey = buffer[readIdx];
            switch (buffer[readIdx++]) {
                case 0x07:
                    readIdx = processOptionsMap(apdu, buffer, readIdx, lc, true);
                    continue;
                case 0x08: // pinUvAuthParam
                    rejectPinUvAuthParam(apdu, buffer, readIdx, lc);
                    continue;
                default:
                    break;
            }
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        // rk:true is mandatory for this appliance (only resident credentials exist).
        if (!transientStorage.hasRKOption()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
        }

        // ---- Allocate working scratch, then create the key (first call) or reuse it ----
        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.ANYWHERE);
        final short scratchRPIDHashOffset = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashOffset);
        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);
        final short scratchPublicKeyHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH, BufferManager.ANYWHERE);
        final short scratchPublicKeyOffset = bufferManager.getOffsetForHandle(scratchPublicKeyHandle);
        final byte[] scratchPublicKeyBuffer = bufferManager.getBufferForHandle(apdu, scratchPublicKeyHandle);
        final boolean hasRkSlot = numResidentCredentials > 0 && residentKeys[0] != null;
        if (hasRkSlot) {
            // Reuse existing resident key; return a fresh makeCredential attestation.
            loadResidentIntoWorkingAttester(apdu, (short) 0);
            residentKeys[0].packCredentialId(scratchCredBuffer, scratchCredOffset);
            residentKeys[0].unpackPublicKey(scratchPublicKeyBuffer, scratchPublicKeyOffset);
        } else {
            P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
            if (!makeGoodKeyPair(ecKeyPair, scratchPublicKeyBuffer, scratchPublicKeyOffset)) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_OTHER);
            }
            final short privScratchHandle = bufferManager.allocate(apdu, KEY_POINT_LENGTH,
                    BufferManager.NOT_APDU_BUFFER);
            final short privScratchOffset = bufferManager.getOffsetForHandle(privScratchHandle);
            final byte[] privScratchBuffer = bufferManager.getBufferForHandle(apdu, privScratchHandle);
            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                numResidentCredentials = 1;
                // Uncompressed SEC1 public key for later makeCredential reuse.
                residentKeys[0] = new ResidentKeyData(
                        scratchPublicKeyBuffer, scratchPublicKeyOffset, PUB_KEY_LENGTH);
                ((ECPrivateKey) ecKeyPair.getPrivate()).getS(privScratchBuffer, privScratchOffset);
                residentKeys[0].setPrivateKey(privScratchBuffer, privScratchOffset);
                residentKeys[0].packCredentialId(scratchCredBuffer, scratchCredOffset);
                ok = true;
            } catch (Exception e) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
            } finally {
                Util.arrayFillNonAtomic(privScratchBuffer, privScratchOffset, KEY_POINT_LENGTH, (byte) 0);
                bufferManager.release(apdu, privScratchHandle, KEY_POINT_LENGTH);
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        }
        // ---- Build the attestation object into bufferMem, sign authData||clientDataHash ----
        final short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, BufferManager.ANYWHERE);
        final short clientDataHashScratchOffset = bufferManager.getOffsetForHandle(clientDataHashHandle);
        final byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        Util.arrayCopyNonAtomic(buffer, clientDataHashIdx, clientDataHashBuffer, clientDataHashScratchOffset,
                CLIENT_DATA_HASH_LEN);
        short outputLen = 0;
        bufferMem[outputLen++] = 0x00;        // CTAP status OK
        bufferMem[outputLen++] = (byte) 0xA3; // CBOR map: 3 entries (fmt, authData, attStmt)
        outputLen = Util.arrayCopyNonAtomic(CannedCBOR.MAKE_CREDENTIAL_RESPONSE_PREAMBLE, (short) 0,
                bufferMem, outputLen, (short) CannedCBOR.MAKE_CREDENTIAL_RESPONSE_PREAMBLE.length);
        byte flags = 0x41; // AT (attested credential data) + UP (user present)
        final short adLen = getAuthDataLen(true);
        final short adAddlBytes = writeAD(bufferMem, outputLen, adLen, scratchRPIDHashBuffer, scratchRPIDHashOffset,
                scratchPublicKeyBuffer, (short) (scratchPublicKeyOffset + 1), flags,
                scratchCredBuffer, scratchCredOffset);
        final short offsetForStartOfAuthData = (short) (outputLen + adAddlBytes);
        outputLen = (short) (outputLen + adLen + adAddlBytes);
        Util.arrayCopyNonAtomic(clientDataHashBuffer, clientDataHashScratchOffset,
                bufferMem, outputLen, CLIENT_DATA_HASH_LEN);
        boolean selfAttestation = attestationKey == null;
        byte[] attestationPreamble;
        if (selfAttestation) {
            if (!hasRkSlot) {
                attester.init(ecKeyPair.getPrivate(), Signature.MODE_SIGN);
            }
            attestationPreamble = CannedCBOR.SELF_ATTESTATION_STATEMENT_PREAMBLE;
        } else {
            attester.init(attestationKey, Signature.MODE_SIGN);
            attestationPreamble = CannedCBOR.BASIC_ATTESTATION_STATEMENT_PREAMBLE;
        }
        final short sigLength = attester.sign(bufferMem, offsetForStartOfAuthData,
                (short) (adLen + CLIENT_DATA_HASH_LEN), bufferMem,
                (short) (outputLen + attestationPreamble.length + 2));
        ecKeyPair.getPrivate().clearKey();
        outputLen = Util.arrayCopyNonAtomic(attestationPreamble, (short) 0,
                bufferMem, outputLen, (short) attestationPreamble.length);
        if (sigLength < 24) {
            Util.arrayCopyNonAtomic(bufferMem, (short) (outputLen + 2), bufferMem, (short) (outputLen + 1), sigLength);
        } else if (sigLength > 255) {
            Util.arrayCopyNonAtomic(bufferMem, (short) (outputLen + 2), bufferMem, (short) (outputLen + 3), sigLength);
        }
        outputLen = encodeIntLenTo(bufferMem, outputLen, sigLength, true);
        outputLen += sigLength;
        transientStorage.setStreamX5CLater(false);
        if (!selfAttestation) {
            outputLen = Util.arrayCopyNonAtomic(CannedCBOR.X5C, (short) 0,
                    bufferMem, outputLen, (short) CannedCBOR.X5C.length);
            final short x5cLen = (short) attestationData.length;
            if ((short) (outputLen + x5cLen) <= (short) bufferMem.length) {
                outputLen = Util.arrayCopyNonAtomic(attestationData, (short) 0,
                        bufferMem, outputLen, x5cLen);
            } else {
                transientStorage.setStreamX5CLater(true);
            }
        }
        // The NDEF companion owns a separate key and signs its own URL; nothing to share.
        doSendResponse(apdu, outputLen);
    }

    /**
     * Handles CTAP {@code authenticatorGetAssertion} (0x02).
     *
     * <p>Request CBOR map (ascending integer keys):
     * <pre>
     *   0x01 rpId             text string (only used to compute the RP-ID hash)
     *   0x02 clientDataHash   byte string, 32 bytes
     *   0x05 options          {up} honored; {uv:true} rejected
     *   0x06 pinUvAuthParam   always rejected
     * </pre>
     * {@code allowList} (0x03) is intentionally ignored: there is one credential, so the
     * resident key is always used if present ({@code NO_CREDENTIALS} otherwise). Signs
     * {@code authData || clientDataHash} and returns the credential, authData, signature,
     * and {@code user.id} (= the compressed public key).
     */
    private void getAssertion(final APDU apdu, final short lc, final byte[] buffer) {
        short readIdx = 1;
        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.NOT_APDU_BUFFER);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        final short scratchRPIDHashIdx = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN,
                BufferManager.NOT_APDU_BUFFER);
        final byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        final short clientDataHashIdx = bufferManager.getOffsetForHandle(clientDataHashHandle);
        final short credStorageHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short credStorageOffset = bufferManager.getOffsetForHandle(credStorageHandle);
        final byte[] credStorageBuffer = bufferManager.getBufferForHandle(apdu, credStorageHandle);
        if (lc == 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if ((buffer[readIdx] & 0xF0) != 0xA0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        final short numParams = getMapEntryCount(apdu, buffer[readIdx++]);
        if (numParams < 2) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] != 0x01) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        short rpIdLen;
        if (buffer[readIdx] == 0x78) {
            readIdx++;
            // One-byte length: read unsigned so 128-255 is not misread as negative.
            rpIdLen = ub(buffer[readIdx++]);
        } else if (buffer[readIdx] >= 0x61 && buffer[readIdx] < 0x78) {
            rpIdLen = (short) (buffer[readIdx] - 0x60);
            readIdx++;
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return;
        }
        final short rpIdIdx = readIdx;
        readIdx += rpIdLen;
        // The RP ID must leave room for the mandatory clientDataHash key that follows;
        // reject a length that runs past the request rather than dereferencing OOB.
        if (readIdx >= lc) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }
        if (buffer[readIdx++] != 0x02) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] != 0x58 || buffer[readIdx++] != CLIENT_DATA_HASH_LEN) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        Util.arrayCopyNonAtomic(buffer, readIdx, clientDataHashBuffer, clientDataHashIdx, CLIENT_DATA_HASH_LEN);
        readIdx += CLIENT_DATA_HASH_LEN;
        sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashIdx);
        defaultOptions();
        byte lastMapKey = 0x02;
        for (short i = 2; i < numParams; i++) {
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
            }
            if (buffer[readIdx] <= lastMapKey) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            lastMapKey = buffer[readIdx];
            switch (buffer[readIdx++]) {
                case 0x05:
                    readIdx = processOptionsMap(apdu, buffer, readIdx, lc, false);
                    continue;
                case 0x06: // pinUvAuthParam
                    rejectPinUvAuthParam(apdu, buffer, readIdx, lc);
                    continue;
                default:
                    break;
            }
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        if (!hasUsableResidentKey()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }
        loadResidentIntoWorkingAttester(apdu, (short) 0);
        residentKeys[0].packCredentialId(credStorageBuffer, credStorageOffset);
        byte[] outputBuffer = bufferMem;
        short outputIdx = 0;
        outputBuffer[outputIdx++] = FIDOConstants.CTAP2_OK;
        outputBuffer[outputIdx++] = (byte) 0xA4; // credential, authData, sig, user
        outputBuffer[outputIdx++] = 0x01;
        outputIdx = packCredentialId(credStorageBuffer, credStorageOffset, outputBuffer, outputIdx);
        outputBuffer[outputIdx++] = 0x02;
        // UP unless the platform asked for a silent assertion (up:false).
        byte flags = transientStorage.hasUPOption() ? (byte) 0x01 : (byte) 0x00;
        short adLen = getAuthDataLen(false);
        final short adAddlBytes = writeADBasic(outputBuffer, adLen, outputIdx, flags,
                scratchRPIDHashBuffer, scratchRPIDHashIdx);
        final short startOfAD = (short) (outputIdx + adAddlBytes);
        outputIdx = (short) (startOfAD + adLen);
        Util.arrayCopyNonAtomic(clientDataHashBuffer, clientDataHashIdx, outputBuffer, outputIdx, CLIENT_DATA_HASH_LEN);
        final short sigScratchOff = (short) (outputIdx + CLIENT_DATA_HASH_LEN);
        final short sigLength = attester.sign(outputBuffer, startOfAD,
                (short) (adLen + CLIENT_DATA_HASH_LEN), outputBuffer, (short) (sigScratchOff + 3));
        outputBuffer[outputIdx++] = 0x03;
        outputIdx = encodeIntLenTo(outputBuffer, outputIdx, sigLength, true);
        Util.arrayCopyNonAtomic(outputBuffer, (short) (sigScratchOff + 3), outputBuffer, outputIdx, sigLength);
        outputIdx += sigLength;
        outputBuffer[outputIdx++] = 0x04;
        outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.SINGLE_ID_MAP_PREAMBLE, (short) 0,
                outputBuffer, outputIdx, (short) CannedCBOR.SINGLE_ID_MAP_PREAMBLE.length);
        outputIdx = encodeIntLenTo(outputBuffer, outputIdx, CREDENTIAL_ID_LEN, true);
        Util.arrayCopyNonAtomic(credStorageBuffer, credStorageOffset,
                outputBuffer, outputIdx, CREDENTIAL_ID_LEN);
        outputIdx += CREDENTIAL_ID_LEN;
        ecKeyPair.getPrivate().clearKey();
        doSendResponse(apdu, outputIdx);
    }

    /**
     * If the given byte represents a CBOR map, return the number of entries in that
     * map.
     * Otherwise, return an error to the platform.
     *
     * @param apdu               Request/response object
     * @param cborMapDeclaration Byte declaring a CBOR map
     *
     * @return The number of map entries in the given CBOR object
     */
    private short getMapEntryCount(APDU apdu, byte cborMapDeclaration) {
        short sb = ub(cborMapDeclaration);
        if (sb < 0x00A0 || sb > 0x00B7) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        return (short) (sb - 0x00A0);
    }

    /**
     * Creates a "good" (32-byte-private-key) EC keypair.
     *
     * @param keyPair         After call, this is set to a usable keypair. Before
     *                        call, must be initialized with P256
     *                        curve points.
     * @param publicKeyBuffer Buffer into which to write the public key - must have
     *                        PUBLIC_KEY_LENGTH bytes available.
     *                        If null, keypair will be created "blind" and public
     *                        key not stored anywhere.
     * @param publicKeyOffset Offset into write buffer
     * @return true if successful, false if not.
     */
    private boolean makeGoodKeyPair(KeyPair keyPair, byte[] publicKeyBuffer, short publicKeyOffset) {
        keyPair.genKeyPair();

        if (publicKeyBuffer == null) {
            return true;
        }
        short sLen = ((ECPrivateKey) keyPair.getPrivate()).getS(publicKeyBuffer, publicKeyOffset);
        short wLen = ((ECPublicKey) keyPair.getPublic()).getW(publicKeyBuffer, publicKeyOffset);
        if (sLen > KEY_POINT_LENGTH) {
            return false;
        }
        return wLen == PUB_KEY_LENGTH && publicKeyBuffer[publicKeyOffset] == 0x04;
    }

    private short readCborStrKeyLen(APDU apdu, byte[] buffer, short readIdx, short lc) {
        short keyDef = ub(buffer[readIdx]);
        if (keyDef == 0x0078) {
            if ((short) (readIdx + 1) >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            return ub(buffer[(short) (readIdx + 1)]);
        }
        if (keyDef >= 0x0060 && keyDef < 0x0078) {
            return (short) (keyDef - 0x0060);
        }
        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        return 0;
    }

    private short cborTextKeyContentIdx(short readIdx, byte keyDef) {
        if (keyDef == 0x78) {
            return (short) (readIdx + 2);
        }
        return (short) (readIdx + 1);
    }

    // =====================================================================================
    // CBOR request parsing helpers (all operate on the raw request buffer + a read cursor)
    // =====================================================================================

    /**
     * Advances past one CBOR value at {@code readIdx}, recursing into arrays/maps, and
     * returns the index just after it. Only the CBOR major types this applet can receive
     * are handled; anything else is a {@code CBOR_UNEXPECTED_TYPE} error. Every recursion
     * re-checks bounds against {@code lc}, so truncated input fails as a clean error.
     */
    private short skipCborValue(APDU apdu, byte[] buffer, short readIdx, short lc) {
        if (readIdx >= lc || readIdx < 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
        }

        short s = ub(buffer[readIdx]);

        if ((s >= 0x0000 && s <= 0x0017) || (s >= 0x0020 && s <= 0x0037) || s == 0x00F4 || s == 0x00F5 || s == 0x00F6) {
            return (short) (readIdx + 1);
        }
        if (s == 0x0018 || s == 0x0038) {
            return (short) (readIdx + 2);
        }
        if (s == 0x0019 || s == 0x0039) {
            return (short) (readIdx + 3);
        }
        if (s == 0x0058 || s == 0x0078) {
            return (short) (readIdx + 2 + ub(buffer[(short) (readIdx + 1)]));
        }
        if (s == 0x0059 || s == 0x0079) {
            short len = Util.getShort(buffer, (short) (readIdx + 1));
            if (len < 0) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            return (short) (readIdx + 3 + len);
        }
        if (s >= 0x0040 && s <= 0x0057) {
            return (short) (readIdx + 1 + s - 0x0040);
        }
        if (s >= 0x0060 && s <= 0x0077) {
            return (short) (readIdx + 1 + s - 0x0060);
        }
        if (s >= 0x0080 && s <= 0x0097) {
            readIdx++;
            for (short i = 0; i < (short) (s - 0x0080); i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s >= 0x00A0 && s <= 0x00B7) {
            readIdx++;
            for (short i = 0; i < (short) (s - 0x00A0); i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = skipCborValue(apdu, buffer, readIdx, lc);
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0x00B8) {
            short l = ub(buffer[(short) (readIdx + 1)]);
            readIdx += 2;
            for (short i = 0; i < l; i++) {
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = skipCborValue(apdu, buffer, readIdx, lc);
                if (readIdx >= lc || readIdx < 0) {
                    sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
                }
                readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }

        sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        return readIdx;
    }

    /**
     * Parses the {@code rp} map, locating its {@code id} text string. The (offset, length)
     * of that id is stashed in {@link TransientStorage} for the caller to hash; other rp
     * fields are skipped. Errors {@code MISSING_PARAMETER} if no {@code id} is present.
     */
    private short readRpIdMap(APDU apdu, byte[] buffer, short readIdx, short lc) {
        transientStorage.readyStoredVars();
        short mapDef = ub(buffer[readIdx++]);
        short mapEntryCount;
        if ((mapDef & 0xF0) == 0xA0) {
            mapEntryCount = (short) (mapDef & 0x0F);
        } else if ((mapDef & 0xF0) == 0xB0 && mapDef < ub((byte) 0xB8)) {
            mapEntryCount = (short) ((mapDef & 0x0F) + 16);
        } else if (mapDef == (byte) 0xB8) {
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            mapEntryCount = ub(buffer[readIdx++]);
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return readIdx;
        }

        boolean foundId = false;
        for (short i = 0; i < mapEntryCount; i++) {
            byte keyDef = buffer[readIdx];
            short keyLen = readCborStrKeyLen(apdu, buffer, readIdx, lc);
            short keyIdx = cborTextKeyContentIdx(readIdx, keyDef);
            readIdx = (short) (keyIdx + keyLen);
            final boolean isId = (keyLen == 2 && buffer[keyIdx] == 'i' && buffer[(short) (keyIdx + 1)] == 'd');
            short valIdx = readIdx;
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            if (!isId) {
                continue;
            }
            short valDef = ub(buffer[valIdx]);
            short idLen = 0;
            short idIdx = 0;
            if (valDef >= 0x0060 && valDef < 0x0078) {
                idLen = (short) (valDef - 0x0060);
                idIdx = (short) (valIdx + 1);
            } else if (valDef == 0x0078) {
                idLen = ub(buffer[(short) (valIdx + 1)]);
                idIdx = (short) (valIdx + 2);
            } else {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }
            if (idLen > 255) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            foundId = true;
            transientStorage.setStoredVars(idIdx, (byte) idLen);
        }

        if (!foundId) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        return readIdx;
    }

    /**
     * Parses the {@code user} map, locating its {@code id} byte string and stashing its
     * (offset, length) in {@link TransientStorage}. The value is only length-validated by
     * the caller and then discarded (assertion {@code user.id} is the public key, not this).
     */
    private short readUserMap(APDU apdu, byte[] buffer, short readIdx, short lc) {
        transientStorage.readyStoredVars();
        short mapDef = ub(buffer[readIdx++]);
        short mapEntryCount;
        if ((mapDef & 0xF0) == 0xA0) {
            mapEntryCount = (short) (mapDef & 0x0F);
        } else if ((mapDef & 0xF0) == 0xB0 && mapDef < ub((byte) 0xB8)) {
            mapEntryCount = (short) ((mapDef & 0x0F) + 16);
        } else if (mapDef == (byte) 0xB8) {
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            mapEntryCount = ub(buffer[readIdx++]);
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return readIdx;
        }

        boolean foundId = false;
        for (short i = 0; i < mapEntryCount; i++) {
            byte keyDef = buffer[readIdx];
            short keyLen = readCborStrKeyLen(apdu, buffer, readIdx, lc);
            short keyIdx = cborTextKeyContentIdx(readIdx, keyDef);
            readIdx = (short) (keyIdx + keyLen);
            final boolean isId = (keyLen == 2 && buffer[keyIdx] == 'i' && buffer[(short) (keyIdx + 1)] == 'd');
            short valIdx = readIdx;
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            short valDef = ub(buffer[valIdx]);
            short valLen;
            short valStart;
            if (valDef >= 0x0040 && valDef < 0x0058) {
                valLen = (short) (valDef - 0x0040);
                valStart = (short) (valIdx + 1);
            } else if (valDef >= 0x0060 && valDef < 0x0078) {
                valLen = (short) (valDef - 0x0060);
                valStart = (short) (valIdx + 1);
            } else if (valDef == 0x0058 || valDef == 0x0078) {
                valLen = ub(buffer[(short) (valIdx + 1)]);
                valStart = (short) (valIdx + 2);
            } else {
                continue;
            }
            if (valLen > 255) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
            }
            if (isId && valDef >= 0x0040 && valDef <= 0x0058) {
                foundId = true;
                transientStorage.setStoredVars(valStart, (byte) valLen);
            }
        }

        if (!foundId) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        return readIdx;
    }

    private short requireEs256PubKeyParams(APDU apdu, byte[] buffer, short readIdx, short lc, byte arrayType) {
        final short numPubKeys = (short) (arrayType & 0x0F);
        boolean foundEs256 = false;
        for (short i = 0; i < numPubKeys; i++) {
            if (isEs256PubKeyParam(apdu, buffer, readIdx, lc)) {
                foundEs256 = true;
            }
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        if (!foundEs256) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        return readIdx;
    }

    private boolean isEs256PubKeyParam(APDU apdu, byte[] buffer, short readIdx, short lc) {
        short mapDef = ub(buffer[readIdx++]);
        if ((mapDef & 0xF0) != 0xA0) {
            return false;
        }
        short mapEntryCount = (short) (mapDef & 0x0F);
        boolean hasEs256 = false;
        boolean hasPublicKey = false;
        for (short i = 0; i < mapEntryCount; i++) {
            byte keyDef = buffer[readIdx];
            short keyLen = readCborStrKeyLen(apdu, buffer, readIdx, lc);
            short keyIdx = cborTextKeyContentIdx(readIdx, keyDef);
            readIdx = (short) (keyIdx + keyLen);
            short valIdx = readIdx;
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
            if (keyLen == 3 && buffer[keyIdx] == 'a' && buffer[(short) (keyIdx + 1)] == 'l'
                    && buffer[(short) (keyIdx + 2)] == 'g') {
                if (buffer[valIdx] == 0x26) {
                    hasEs256 = true;
                }
            } else if (keyLen == 4 && buffer[keyIdx] == 't' && buffer[(short) (keyIdx + 1)] == 'y'
                    && buffer[(short) (keyIdx + 2)] == 'p' && buffer[(short) (keyIdx + 3)] == 'e') {
                short valDef = ub(buffer[valIdx]);
                short valLen;
                short valStart;
                if (valDef >= 0x0060 && valDef < 0x0078) {
                    valLen = (short) (valDef - 0x0060);
                    valStart = (short) (valIdx + 1);
                } else if (valDef == 0x0078) {
                    valLen = ub(buffer[(short) (valIdx + 1)]);
                    valStart = (short) (valIdx + 2);
                } else {
                    continue;
                }
                hasPublicKey = valLen == (short) CannedCBOR.PUBLIC_KEY_TYPE.length
                        && Util.arrayCompare(buffer, valStart,
                                CannedCBOR.PUBLIC_KEY_TYPE, (short) 0, valLen) == 0;
            }
        }
        return hasEs256 && hasPublicKey;
    }

    /**
     * Write the portions of an authData block that are used for both makeCredential
     * and getAssertion
     *
     * @param outBuf     Buffer into which to write
     * @param adLen      Length of the overall AD block
     * @param writeIdx   Write index into bufferMem
     * @param flags      CTAP2 "flags" byte value
     * @param rpIdBuffer Buffer containing a hash of the RP ID
     * @param rpIdOffset Offset of the RP ID hash in the given buffer
     *
     * @return Additional bytes used for AD basic header beyond the minimum
     */
    private short writeADBasic(byte[] outBuf, short adLen, short writeIdx, byte flags, byte[] rpIdBuffer,
            short rpIdOffset) {
        short ow = writeIdx;
        writeIdx = encodeIntLenTo(outBuf, writeIdx, adLen, true);

        short adAddlBytes = (short) (writeIdx - ow);

        // RPID hash
        writeIdx = Util.arrayCopyNonAtomic(rpIdBuffer, rpIdOffset, outBuf, writeIdx, RP_HASH_LEN);

        outBuf[writeIdx++] = flags; // flags

        // counter
        encodeCounter(outBuf, writeIdx);

        return adAddlBytes;
    }

    /**
     * Pack an EC public key into the given buffer
     *
     * @param outBuf       Buffer into which to write
     * @param outputLen    The current index in the output buffer (begin writing
     *                     here)
     * @param pubKeyBuffer A buffer containing the public key to be written in the
     *                     format X || Y
     * @param pubKeyOffset An index pointing to the X-coordinate of the public key
     *
     * @return New index in the output buffer after writes
     */
    private short writePubKey(byte[] outBuf, short outputLen, byte[] pubKeyBuffer, short pubKeyOffset) {
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, pubKeyOffset,
                outBuf, outputLen, KEY_POINT_LENGTH);
        outBuf[outputLen++] = 0x22; // map key: y-coordinate
        outBuf[outputLen++] = 0x58; // byte string with one-byte length to follow
        outBuf[outputLen++] = (byte) KEY_POINT_LENGTH;
        outputLen = Util.arrayCopyNonAtomic(pubKeyBuffer, (short) (pubKeyOffset + KEY_POINT_LENGTH),
                outBuf, outputLen, KEY_POINT_LENGTH);
        return outputLen;
    }

    private void encodeCounter(byte[] buf, short off) {
        random.generateData(buf, off, (short) 1);
        boolean ok = counter.increment((short) ((buf[off] & 0x0E) + 1));
        if (!ok) {
            throwException(ISO7816.SW_FILE_FULL);
        }
        counter.pack(buf, off);
    }

    private static short ub(byte b) {
        return (short) (0xFF & b);
    }

    /**
     * Guards a read of {@code need} bytes starting at {@code offset} against the end of
     * the install parameter buffer. Prevents over-reads past the supplied application data
     * during installation.
     */
    private static void requireInstallBytes(short offset, short need, short endOffset) {
        if ((short) (offset + need) > endOffset) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * Sets in-memory variables capturing possible incoming CTAP options to their
     * default values
     */
    private void defaultOptions() {
        transientStorage.defaultOptions();
    }

    private short encodeIntLenTo(byte[] outBuf, short writeIdx, short v, boolean byteString) {
        if (v < 24) {
            outBuf[writeIdx++] = (byte) ((byteString ? 0x40 : 0x60) + v);
        } else if (v < 256) {
            outBuf[writeIdx++] = (byte) (byteString ? 0x58 : 0x78);
            outBuf[writeIdx++] = (byte) v;
        } else {
            outBuf[writeIdx++] = (byte) (byteString ? 0x59 : 0x79);
            writeIdx = Util.setShort(outBuf, writeIdx, v);
        }
        return writeIdx;
    }

    private short loadAttestationPrivateKey(byte[] params, short offset) {
        attestationKey = getECPrivKey(false, false);
        P256Constants.setCurve(attestationKey);
        attestationKey.setS(params, offset, KEY_POINT_LENGTH);
        return KEY_POINT_LENGTH;
    }

    /**
     * Sets up state tracking for a chained (long) response to the platform, and
     * sends the appropriate status code.
     * Should only be called after the first packet in the chain is sent.
     *
     * @param offset    The offset into the response buffer from which to begin the
     *                  next packet
     * @param remaining The total number of bytes remaining after the already-sent
     *                  packet
     */
    private void setupChainedResponse(short offset, short remaining) {
        transientStorage.setOutgoingContinuation(offset, remaining);
        if (remaining >= 256) {
            // at least ANOTHER full chunk remains
            throwException(ISO7816.SW_BYTES_REMAINING_00, false);
        } else {
            // exactly one more chunk remains
            throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + remaining), false);
        }
    }

    /**
     * Pack a credential ID into a CBOR public-key credential descriptor map.
     *
     * @param credBuffer  Buffer containing credential ID
     * @param credOffset  Offset of credential ID in input buffer
     * @param writeBuffer Output buffer into which to write CBOR
     * @param writeOffset Write index into output buffer
     *
     * @return New write index into output buffer, after writing credential CBOR
     */
    private short packCredentialId(byte[] credBuffer, short credOffset, byte[] writeBuffer, short writeOffset) {
        writeBuffer[writeOffset++] = (byte) 0xA2; // map: two entries

        writeBuffer[writeOffset++] = 0x62; // string - two bytes long
        writeBuffer[writeOffset++] = 0x69; // i
        writeBuffer[writeOffset++] = 0x64; // d
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, CREDENTIAL_ID_LEN, true);
        writeOffset = Util.arrayCopyNonAtomic(credBuffer, credOffset,
                writeBuffer, writeOffset, CREDENTIAL_ID_LEN);

        writeBuffer[writeOffset++] = 0x64; // string - four bytes long
        writeBuffer[writeOffset++] = 0x74; // t
        writeBuffer[writeOffset++] = 0x79; // y
        writeBuffer[writeOffset++] = 0x70; // p
        writeBuffer[writeOffset++] = 0x65; // e
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length, false);
        writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_TYPE, (short) 0,
                writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length);

        return writeOffset;
    }

    /**
     * Packs a low-valued integer as a CBOR value into a given buffer
     *
     * @param outBuf      Buffer into which to write
     * @param writeOffset Write offset into given buffer
     * @param v           Value to pack
     *
     * @return New write offset into given buffer
     */
    private short encodeIntTo(byte[] outBuf, short writeOffset, short v) {
        if (v < 24) {
            outBuf[writeOffset++] = (byte) v;
        } else if (v < 256) {
            outBuf[writeOffset++] = 0x18; // Integer stored in one byte
            outBuf[writeOffset++] = (byte) v;
        } else {
            outBuf[writeOffset++] = 0x19; // Integer stored in two bytes
            writeOffset = Util.setShort(outBuf, writeOffset, v);
        }
        return writeOffset;
    }

    /**
     * Gets an EC sig object
     *
     * @return An elliptic curve signature object suitable for the FIDO2 standard -
     *         ECDSA-SHA256
     */
    private Signature getECSig() {
        return Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    /**
     * Gets an elliptic curve private key object, preferring transient memory.
     *
     * @param forceAllowTransient If true, try transient key types first
     * @param allowDeselectMemory If true, also try CLEAR_ON_DESELECT transient keys
     * @return An uninitialized EC private key
     */
    private ECPrivateKey getECPrivKey(boolean forceAllowTransient, boolean allowDeselectMemory) {
        if (forceAllowTransient) {
            if (allowDeselectMemory) {
                try {
                    return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                            KeyBuilder.LENGTH_EC_FP_256, false);
                } catch (CryptoException e) {
                    // Fall through to RESET or persistent.
                }
            }

            try {
                return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET,
                        KeyBuilder.LENGTH_EC_FP_256, false);
            } catch (CryptoException e) {
                // Fall through to persistent.
            }
        }

        return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }

    /**
     * Allocates a new byte buffer.
     *
     * @param len   Number of bytes to allocate
     * @param inRAM If true, prefer RAM (still fall back to flash)
     * @return Newly created byte array
     */
    private byte[] getTempOrFlashByteBuffer(short len, boolean inRAM) {
        if (inRAM) {
            return JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        }

        return new byte[len];
    }

    // =====================================================================================
    // Attestation certificate loading (vendor command 0x46)
    //
    // Switches from self-attestation to basic (x5c) attestation. Gated by install param
    // 0x00 AND only while the signature counter is zero (before any signing), so the
    // attestation identity cannot be changed after the card is in use. The chain arrives
    // over one or more (chained) APDUs: Start parses the header + optional private key,
    // Continue appends the remaining certificate bytes.
    // =====================================================================================

    /**
     * Initialize non-self attestation mode.
     *
     * This installs an AAGUID and a certificate chain for signing credentials,
     * instead of them being signed with their own private keys.
     *
     * @param apdu   Optional (nullable) APDU context object
     * @param params Byte array of encoded parameters:
     *               - aaguid
     *               - private key point
     *               - certificate chain. CBOR-encoded
     * @param offset Offset into params array of start of data
     * @param length Length of parameter data loaded in buffer
     * @return true if we're done reading the keys
     */
    private boolean initAttestationKeyStart(APDU apdu, byte[] params, short offset, short length) {
        if (!counter.isZero()) {
            if (apdu != null) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
            }
            throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (!attestationSwitchingEnabled) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
        }

        short minLength = (short) (aaguid.length + 4);
        if (attestationKey == null) {
            minLength += KEY_POINT_LENGTH;
        }

        if (length <= minLength) {
            if (apdu != null) {
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
            }
            throwException(ISO7816.SW_DATA_INVALID);
        }

        JCSystem.beginTransaction();
        boolean success = false;
        try {
            attestationSwitchingEnabled = false; // We're loading a cert here and now.

            Util.arrayCopy(params, offset, aaguid, (short) 0, (short) aaguid.length);
            offset += (short) aaguid.length;
            short amountToRead = (short) (length - aaguid.length - 2);

            if (attestationKey == null) {
                offset += loadAttestationPrivateKey(params, offset);
                amountToRead -= KEY_POINT_LENGTH;
            }

            final short expectedLength = Util.getShort(params, offset);
            offset += 2;

            if (amountToRead > expectedLength) {
                if (apdu != null) {
                    sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
                }
                throwException(ISO7816.SW_DATA_INVALID);
            }

            if ((params[offset] & 0xF0) != 0x80) {
                // Attestation chain must be a CBOR array of at most 15 certs.
                throwException(ISO7816.SW_DATA_INVALID);
            }

            attestationData = new byte[expectedLength];
            filledAttestationData = amountToRead;
            Util.arrayCopy(params, offset,
                    attestationData, (short) 0, amountToRead);

            if (filledAttestationData == attestationData.length) {
                if (apdu != null) {
                    final byte[] buffer = apdu.getBuffer();
                    buffer[0] = FIDOConstants.CTAP2_OK;
                    sendNoCopy(apdu, (short) 1);
                }
                success = true;
                return true;
            }

            success = true;
        } finally {
            if (success) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        return false;
    }

    /**
     * Continue loading part of an attestation key; used as part of initial setup
     * for basic auth.
     *
     * @param apdu   Request/response context object
     * @param buffer Incoming request buffer
     * @param offset Read offset in incoming buffer
     * @param lc     Declared incoming request length
     * @return true if attestation key now completely loaded; false otherwise
     */
    private boolean initAttestationKeyContinue(APDU apdu, byte[] buffer, short offset, short lc) {
        if (attestationData == null || filledAttestationData == attestationData.length) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NOT_ALLOWED);
        }
        final short amountRemaining = (short) (attestationData.length - filledAttestationData);
        if (lc > amountRemaining) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_LENGTH);
        }
        JCSystem.beginTransaction();
        boolean ok = false;
        boolean done;
        try {
            Util.arrayCopy(buffer, offset,
                    attestationData, filledAttestationData, lc);
            filledAttestationData += lc;
            done = filledAttestationData == attestationData.length;
            if (done) {
                attestationSwitchingEnabled = false;
            }
            ok = true;
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }

        if (done) {
            final byte[] apduBuf = apdu.getBuffer();
            apduBuf[0] = FIDOConstants.CTAP2_OK;
            sendNoCopy(apdu, (short) 1);
        }
        return done;
    }

    /**
     * Initialize the per-credential key object.
     *
     * @param ecPairInRam If true, try to place the private key in transient memory
     */
    private void initCredKey(boolean ecPairInRam) {
        ecKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey(ecPairInRam, false));
        P256Constants.setCurve((ECKey) ecKeyPair.getPrivate());
        P256Constants.setCurve((ECKey) ecKeyPair.getPublic());
    }

    @Override
    /**
     * Single APDU entry point. Dispatch precedence (first match wins):
     * <ol>
     *   <li>Applet SELECT (JCRE selection, or an explicit {@code 00 A4 04 00}).</li>
     *   <li>GET RESPONSE ({@code *C0}): emit the next chunk of a chained response.</li>
     *   <li>Continuation of an in-progress command-chained request (attestation load,
     *       or a generic chained CTAP body being accumulated in {@link #bufferMem}).</li>
     *   <li>Raw U2F ({@code CLA 0x00}): REGISTER (0x01), AUTHENTICATE (0x02), VERSION (0x03).</li>
     *   <li>CTAP ({@code CLA 0x80}, {@code INS 0x10}): dispatch on the first body byte to
     *       makeCredential / getAssertion / getInfo / install-certs.</li>
     * </ol>
     * Anything else falls through to a CLA/INS/P1P2 error. Uncaught runtime exceptions
     * become a non-0x9000 status word (the JavaCard VM bounds-checks all array access, so
     * malformed input degrades to a status word, never memory corruption).
     */
    public void process(APDU apdu) throws ISOException {
        // (1) Selection.
        if (selectingApplet()) {
            handleAppletSelect(apdu);
            return;
        }
        final byte[] apduBytes = apdu.getBuffer();
        final short cla_ins = Util.getShort(apduBytes, ISO7816.OFFSET_CLA);
        final short p1_p2 = Util.getShort(apduBytes, ISO7816.OFFSET_P1);
        if (cla_ins == (short) 0x00A4 && p1_p2 == (short) 0x0400) {
            handleAppletSelect(apdu);
            return;
        }
        // (2) GET RESPONSE: continue streaming a long response. Any other command ends
        //     an outstanding response continuation.
        if (cla_ins == 0x00C0 || cla_ins == (short) 0x80C0) {
            streamOutgoingContinuation(apdu, apduBytes, true);
            return;
        } else {
            transientStorage.clearOutgoingContinuation();
        }
        // (3a) Continuation of a chained attestation-certificate load already in progress.
        if (attestationData != null && filledAttestationData < attestationData.length &&
                transientStorage.getChainIncomingReadOffset() > 0 &&
                bufferMem[0] == FIDOConstants.CMD_INSTALL_CERTS) {
            final short amtRead = apdu.setIncomingAndReceive();
            final short lc = apdu.getIncomingLength();
            if (lc == 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            byte[] buf = fullyReadReq(apdu, lc, amtRead, true);
            final boolean done = initAttestationKeyContinue(apdu, buf, (short) 1, lc);
            transientStorage.resetChainIncomingReadOffset();
            if (!done) {
                transientStorage.increaseChainIncomingReadOffset((short) 1);
            }
            return;
        } else if (apdu.isCommandChainingCLA()) {
            // (3b) First/next packet of a command-chained request. Accumulate into bufferMem;
            //      the first attestation-load packet starts the load, others just advance the
            //      chaining offset until the terminating (non-chaining) packet arrives.
            final short amtRead = apdu.setIncomingAndReceive();
            final short lc = apdu.getIncomingLength();
            if (lc == 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            fullyReadReq(apdu, lc, amtRead, true);
            if (attestationSwitchingEnabled && bufferMem[0] == FIDOConstants.CMD_INSTALL_CERTS) {
                boolean done = false;
                if (attestationData == null) {
                    final short apOffset = (short) (apdu.getOffsetCdata() + 1);
                    final short lcEffective = (short) (lc - apOffset);
                    done = initAttestationKeyStart(apdu, bufferMem, apOffset, lcEffective);
                } else {
                    throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                transientStorage.resetChainIncomingReadOffset();
                if (!done) {
                    transientStorage.increaseChainIncomingReadOffset((short) 1);
                }
                return;
            } else {
                transientStorage.increaseChainIncomingReadOffset(lc);
            }
            return;
        }

        // (4) Raw U2F (ISO 7816 status words, not CTAP error bytes).
        if (cla_ins == 0x0001) {
            transientStorage.clearOutgoingContinuation();
            u2FRegister(apdu);
            return;
        } else if (cla_ins == 0x0002) {
            transientStorage.clearOutgoingContinuation();
            if (apduBytes[ISO7816.OFFSET_P2] != 0x00) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            byte p1 = apduBytes[ISO7816.OFFSET_P1];
            if (p1 != 0x03 && p1 != 0x07 && p1 != 0x08) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            u2FAuthenticate(apdu, p1);
            return;
        } else if (cla_ins == 0x0003) {
            // U2F VERSION
            if (p1_p2 != 0x0000) {
                throwException(ISO7816.SW_INCORRECT_P1P2);
            }
            apdu.setIncomingAndReceive();
            sendByteArray(apdu, CannedCBOR.U2F_V2_RESPONSE,
                    (short) CannedCBOR.U2F_V2_RESPONSE.length);
            return;
        }

        // (5) CTAP over APDU. Require CLA 0x80 / INS 0x10 / P1 in {0x00,0x80} / P2 0x00.
        if (apduBytes[ISO7816.OFFSET_CLA] != (byte) 0x80) {
            throwException(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if (apduBytes[ISO7816.OFFSET_INS] != 0x10) {
            throwException(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if ((apduBytes[ISO7816.OFFSET_P1] != 0x00 && apduBytes[ISO7816.OFFSET_P1] != (byte) 0x80)
                || apduBytes[ISO7816.OFFSET_P2] != 0x00) {
            throwException(ISO7816.SW_INCORRECT_P1P2);
        }
        final short amtRead = apdu.setIncomingAndReceive();
        final short lc = apdu.getIncomingLength();
        if (amtRead == 0) {
            throwException(ISO7816.SW_DATA_INVALID);
        }
        // The CTAP command is the first body byte. lcEffective is the total body length
        // including any already-buffered chained prefix (+1 accounts for that command byte).
        short lcEffective = (short) (lc + 1);
        byte cmdByte = apduBytes[apdu.getOffsetCdata()];
        transientStorage.clearOutgoingContinuation();
        short chainingReadOffset = transientStorage.getChainIncomingReadOffset();
        if (chainingReadOffset > 0) {
            cmdByte = bufferMem[0];
            lcEffective += chainingReadOffset;
        }
        bufferManager.initializeAPDU(apdu);
        byte[] reqBuffer;
        switch (cmdByte) {
            case FIDOConstants.CMD_MAKE_CREDENTIAL:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);
                makeCredential(apdu, lcEffective, reqBuffer);
                break;
            case FIDOConstants.CMD_GET_INFO:
                sendAuthInfo(apdu);
                break;
            case FIDOConstants.CMD_GET_ASSERTION:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);
                getAssertion(apdu, lcEffective, reqBuffer);
                break;
            case FIDOConstants.CMD_INSTALL_CERTS:
                boolean extended = isExtendedApdu(apdu);
                short apOffset;
                lcEffective = (short) (lc - 5);
                reqBuffer = fullyReadReq(apdu, lc, amtRead, !extended);
                if (extended) {
                    apOffset = (short) (apdu.getOffsetCdata() - 2);
                    if (lc > 255) {
                        apOffset += 1;
                        lcEffective -= 1;
                    }
                } else {
                    apOffset = apdu.getOffsetCdata();
                }
                initAttestationKeyStart(apdu, reqBuffer, apOffset, lcEffective);
                break;
            default:
                sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_COMMAND);
                break;
        }
        transientStorage.resetChainIncomingReadOffset();
    }

    /** Called by the JCRE when the applet is deselected; clears all transient state. */
    public void deselect() {
        transientStorage.clearOnDeselect();
    }

    // =====================================================================================
    // Raw U2F (CTAP1) — available only after an attestation certificate is provisioned.
    // Key handle and AppID are intentionally NOT bound to the credential (single-key model);
    // errors are ISO 7816 status words, not CTAP bytes. See docs/capabilities.md.
    // =====================================================================================

    /**
     * U2F REGISTER: returns a standards-shaped registration response for the existing
     * resident key (created via CTAP2 makeCredential). Does not create a new key or push
     * to NDEF again. Requires a provisioned attestation cert and an existing resident key.
     */
    private void u2FRegister(APDU apdu) {
        if (!isU2fProvisioned()) {
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        if (!hasUsableResidentKey()) {
            throwException(ISO7816.SW_WRONG_DATA);
        }

        short attCertLen = 0;
        short attCertStart = 2;
        final byte cborAttLenByte = attestationData[1];
        if (cborAttLenByte <= 0x57 && cborAttLenByte >= 0x40) {
            // CBOR byte string 0x40..0x57 = inline length 0..23 (0x57 must be included).
            attCertLen = (short) (cborAttLenByte - 0x40);
        } else if (cborAttLenByte == 0x58) {
            attCertLen = ub(attestationData[attCertStart++]);
        } else if (cborAttLenByte == 0x59) {
            attCertLen = Util.getShort(attestationData, attCertStart);
            attCertStart += 2;
        } else {
            throwException(ISO7816.SW_DATA_INVALID);
        }

        final short amtRead = apdu.setIncomingAndReceive();
        final short lc = apdu.getIncomingLength();
        if (lc != (short) (CLIENT_DATA_HASH_LEN + RP_HASH_LEN)) {
            throwException(ISO7816.SW_WRONG_LENGTH);
        }
        final byte[] reqBuffer = fullyReadReq(apdu, lc, amtRead, true);
        final short clientDataHashOffset = 0;
        final short appIdHashOffset = CLIENT_DATA_HASH_LEN;

        final short publicKeyHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH,
                BufferManager.NOT_APDU_BUFFER);
        final short publicKeyOffset = bufferManager.getOffsetForHandle(publicKeyHandle);
        final byte[] publicKeyBuffer = bufferManager.getBufferForHandle(apdu, publicKeyHandle);
        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN,
                BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);

        residentKeys[0].unpackPublicKey(publicKeyBuffer, publicKeyOffset);
        residentKeys[0].packCredentialId(scratchCredBuffer, scratchCredOffset);

        final short tbsLen = (short) (1 + RP_HASH_LEN + CLIENT_DATA_HASH_LEN + CREDENTIAL_ID_LEN
                + PUB_KEY_LENGTH);
        final short tbsHandle = bufferManager.allocate(apdu, tbsLen, BufferManager.NOT_APDU_BUFFER);
        final short tbsOffset = bufferManager.getOffsetForHandle(tbsHandle);
        final byte[] tbsBuffer = bufferManager.getBufferForHandle(apdu, tbsHandle);
        short tbsWrite = tbsOffset;
        tbsBuffer[tbsWrite++] = 0x00;
        tbsWrite = Util.arrayCopyNonAtomic(reqBuffer, appIdHashOffset,
                tbsBuffer, tbsWrite, RP_HASH_LEN);
        tbsWrite = Util.arrayCopyNonAtomic(reqBuffer, clientDataHashOffset,
                tbsBuffer, tbsWrite, CLIENT_DATA_HASH_LEN);
        tbsWrite = Util.arrayCopyNonAtomic(scratchCredBuffer, scratchCredOffset,
                tbsBuffer, tbsWrite, CREDENTIAL_ID_LEN);
        Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                tbsBuffer, tbsWrite, PUB_KEY_LENGTH);

        final short sigScratchHandle = bufferManager.allocate(apdu, (short) 80,
                BufferManager.NOT_APDU_BUFFER);
        final short sigScratchOffset = bufferManager.getOffsetForHandle(sigScratchHandle);
        final byte[] sigScratchBuffer = bufferManager.getBufferForHandle(apdu, sigScratchHandle);
        attester.init(attestationKey, Signature.MODE_SIGN);
        final short sigLength = attester.sign(tbsBuffer, tbsOffset, tbsLen,
                sigScratchBuffer, sigScratchOffset);

        short outputLen = 0;
        bufferMem[outputLen++] = 0x05;
        outputLen = Util.arrayCopyNonAtomic(publicKeyBuffer, publicKeyOffset,
                bufferMem, outputLen, PUB_KEY_LENGTH);
        bufferMem[outputLen++] = (byte) CREDENTIAL_ID_LEN;
        outputLen = Util.arrayCopyNonAtomic(scratchCredBuffer, scratchCredOffset,
                bufferMem, outputLen, CREDENTIAL_ID_LEN);
        outputLen = Util.arrayCopyNonAtomic(attestationData, attCertStart,
                bufferMem, outputLen, attCertLen);
        outputLen = Util.arrayCopyNonAtomic(sigScratchBuffer, sigScratchOffset,
                bufferMem, outputLen, sigLength);

        bufferManager.release(apdu, sigScratchHandle, (short) 80);
        bufferManager.release(apdu, tbsHandle, tbsLen);
        bufferManager.release(apdu, scratchCredHandle, CREDENTIAL_ID_LEN);
        bufferManager.release(apdu, publicKeyHandle, PUB_KEY_LENGTH);

        doSendResponse(apdu, outputLen);
    }

    private void u2FAuthenticate(APDU apdu, byte p1) {
        if (!isU2fProvisioned()) {
            throwException(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        short amtRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        final byte[] reqBuffer = fullyReadReq(apdu, lc, amtRead, true);

        final short clientDataHashOffset = 0;
        final short rpIdHashOffset = (short) (clientDataHashOffset + CLIENT_DATA_HASH_LEN);
        final short credIdLenOffset = (short) (rpIdHashOffset + RP_HASH_LEN);
        final short credIdOffset = (short) (credIdLenOffset + 1);
        final short minLc = (short) (credIdOffset - clientDataHashOffset);
        if (lc < minLc) {
            throwException(ISO7816.SW_WRONG_LENGTH);
        }
        final short credIdLen = ub(reqBuffer[credIdLenOffset]);
        if (lc != (short) (minLc + credIdLen)) {
            throwException(ISO7816.SW_WRONG_LENGTH);
        }

        if (!hasUsableResidentKey()) {
            throwException(ISO7816.SW_WRONG_DATA);
        }

        if (p1 == 0x07) {
            // Check-only with a valid key handle: U2F spec requires
            // SW_CONDITIONS_NOT_SATISFIED ("test-of-user-presence required").
            throwException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        loadResidentIntoWorkingAttester(apdu, (short) 0);

        final byte flag_byte = 0x01; // User always present

        final short scratchSigHandle = bufferManager.allocate(apdu,
                (short) (RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5), BufferManager.NOT_APDU_BUFFER);
        final short scratchSigOffset = bufferManager.getOffsetForHandle(scratchSigHandle);
        final byte[] scratchSigBuffer = bufferManager.getBufferForHandle(apdu, scratchSigHandle);

        random.generateData(scratchSigBuffer, scratchSigOffset, (short) 1);
        if (!counter.increment((short) ((scratchSigBuffer[scratchSigOffset] & 0x0E) + 1))) {
            throwException(ISO7816.SW_FILE_FULL);
        }

        final short sigRPIDOffset = scratchSigOffset;
        final short sigFlagsByteOffset = (short) (sigRPIDOffset + RP_HASH_LEN);
        final short sigCounterOffset = (short) (sigFlagsByteOffset + 1);
        final short sigClientDataOffset = (short) (sigCounterOffset + 4);

        Util.arrayCopyNonAtomic(reqBuffer, rpIdHashOffset,
                scratchSigBuffer, sigRPIDOffset, RP_HASH_LEN);
        scratchSigBuffer[sigFlagsByteOffset] = flag_byte;
        counter.pack(scratchSigBuffer, sigCounterOffset);
        Util.arrayCopyNonAtomic(reqBuffer, clientDataHashOffset,
                scratchSigBuffer, sigClientDataOffset, CLIENT_DATA_HASH_LEN);

        final byte[] apduBuf = apdu.getBuffer();
        final short sigLen = attester.sign(scratchSigBuffer, sigRPIDOffset,
                (short) (RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5),
                apduBuf, (short) 5);

        apduBuf[0] = flag_byte;
        counter.pack(apduBuf, (short) 1);
        bufferManager.release(apdu, scratchSigHandle,
                (short) (RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5));
        ecKeyPair.getPrivate().clearKey();
        sendNoCopy(apdu, (short) (sigLen + 5));
    }

    // =====================================================================================
    // Applet lifecycle: install and selection
    // =====================================================================================

    /**
     * JCRE install entry point. Strips the AID/control-info framing to locate the
     * application-data block, then constructs and registers the applet.
     */
    public static void install(byte[] array, short offset, byte length) throws ISOException {
        if (length > 0) {
            short aidLen = ub(array[offset]);
            short infoLen = ub(array[(short) (offset + aidLen + 1)]);
            length = array[(short) (offset + aidLen + infoLen + 2)];
            offset = (short) (offset + aidLen + infoLen + 3);
        }
        FIDO2Applet applet = new FIDO2Applet(array, offset, length);
        applet.register();
    }

    /**
     * Constructs the applet, applying install parameters. The parameter blob is a small
     * CBOR-style map with integer keys (all optional):
     * <pre>
     *   0x00 attestationSwitchingEnabled (bool)   0x09 max RAM scratch
     *   0x0A buffer_mem / maxMsgSize              0x0B flash scratch
     *   0x0F fixed 32-byte attestation private key
     * </pre>
     * Each field read is bounds-checked against the blob (see {@link #requireInstallBytes}).
     * Defaults favor RAM to minimize EEPROM wear.
     */
    private FIDO2Applet(byte[] array, short offset, byte length) {
        attestationSwitchingEnabled = false;
        // Defaults favor RAM-first operation; flash fallback (bufferMem / flashBuffer)
        // causes EEPROM wear when CTAP scratch exhausts transient space. Tune down only
        // after testAll passes with your attestation chain size (see
        // tools/get_install_parameters.py).
        MAX_RAM_SCRATCH_SIZE = 512;
        BUFFER_MEM_SIZE = 2048;
        FLASH_SCRATCH_SIZE = 1024;
        final short initOffset = offset;
        final short endOffset = (short) (initOffset + length);
        if (length > 0) {
            short sb = ub(array[offset++]);
            short numOptions = (short) (sb - 0xA0);
            for (; numOptions > 0; numOptions--) {
                if (offset > (short) (length + initOffset - 1)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                switch (array[offset++]) {
                    case 0x00:
                        requireInstallBytes(offset, (short) 1, endOffset);
                        attestationSwitchingEnabled = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x09:
                        requireInstallBytes(offset, (short) 1, endOffset);
                        if (array[offset] == 0x18) {
                            requireInstallBytes(offset, (short) 2, endOffset);
                            offset++;
                            MAX_RAM_SCRATCH_SIZE = ub(array[offset++]);
                        } else if (array[offset] == 0x19) {
                            requireInstallBytes(offset, (short) 3, endOffset);
                            offset += 3;
                            MAX_RAM_SCRATCH_SIZE = Util.getShort(array, (short) (offset - 2));
                        } else {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x0A:
                        requireInstallBytes(offset, (short) 3, endOffset);
                        if (array[offset++] != 0x19) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        BUFFER_MEM_SIZE = Util.getShort(array, offset);
                        offset += 2;
                        break;
                    case 0x0B:
                        requireInstallBytes(offset, (short) 1, endOffset);
                        if (array[offset] == 0x18) {
                            requireInstallBytes(offset, (short) 2, endOffset);
                            offset++;
                            FLASH_SCRATCH_SIZE = ub(array[offset++]);
                        } else if (array[offset] == 0x19) {
                            requireInstallBytes(offset, (short) 3, endOffset);
                            offset++;
                            FLASH_SCRATCH_SIZE = Util.getShort(array, offset);
                            offset += 2;
                        } else if (ub(array[offset]) <= 0x17) {
                            FLASH_SCRATCH_SIZE = ub(array[offset++]);
                        } else {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x0F:
                        requireInstallBytes(offset, (short) (2 + KEY_POINT_LENGTH), endOffset);
                        if (array[offset++] != 0x58 || array[offset++] != 0x20) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        offset += loadAttestationPrivateKey(array, offset);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }
        residentKeys = new ResidentKeyData[1];
        numResidentCredentials = 0;
        counter = new SigOpCounter();
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        attester = getECSig();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        transientStorage = new TransientStorage();
        initCredKey(true);
    }

}
