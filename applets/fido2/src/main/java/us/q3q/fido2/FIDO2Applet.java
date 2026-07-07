package us.q3q.fido2;

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
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

import org.openjavacard.ndef.stub.NdefKeyStore;

public final class FIDO2Applet extends Applet implements ExtendedLength {

    private static final byte FIRMWARE_VERSION = 0x08;

    private static final byte[] AID = {
            (byte) 0xA0, 0x00, 0x00, 0x06, 0x47,
            0x2F, 0x00, 0x01
    };

    private boolean attestationSwitchingEnabled;
    /** Scratch for decrypting credential material before pushing to NdefApplet (CLEAR_ON_DESELECT). */
    private byte[] ndefPushScratch;
    private static final byte[] NDEF_CLIENT_AID = {
            (byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01
    };
    private static final short COMPRESSED_PUBKEY_LEN = 33;
    /** RP_HASH(32) + privKey(32) + extra(16) + pubXY(64) + compressedPub(33). */
    private static final short NDEF_PUSH_SCRATCH_SIZE = 177;

    private short MAX_RAM_SCRATCH_SIZE;
    private short BUFFER_MEM_SIZE;
    private short FLASH_SCRATCH_SIZE;
    private static final short IV_LEN = 16;
    private short MAX_RESIDENT_RP_ID_LENGTH;
    private static final short MAX_USER_ID_LENGTH = 64;
    private static final short KEY_POINT_LENGTH = 32;
    private static final short RP_HASH_LEN = 32;
    // Encrypted credential payload holds only the private key scalar. The RP ID hash was dropped
    // (RP ID check is skipped at assertion time) and the one-block marker was dropped because the
    // HMAC tag (tagOk) is the real authenticity guarantee; the marker's mixedOk check was redundant.
    private static final short CREDENTIAL_PAYLOAD_LEN = KEY_POINT_LENGTH;
    private static final short CREDENTIAL_ID_LEN = (short) (CREDENTIAL_PAYLOAD_LEN + IV_LEN + 16);
    private static final short PUB_KEY_LENGTH = (short) (2 * KEY_POINT_LENGTH + 1);
    private static final short CLIENT_DATA_HASH_LEN = 32;
    private byte[] bufferMem;
    private final byte[] credentialVerificationKey;
    private final byte[] wrappingKeySpace;
    private final AESKey lowSecurityWrappingKey;
    private final byte[] wrappingKeyValidation;
    private final Cipher symmetricWrapper;
    private final Cipher symmetricUnwrapper;
    private final RandomData random;
    private final SigOpCounter counter;
    private KeyPair ecKeyPair;
    private ECPrivateKey attestationKey;
    private byte[] attestationData;
    private short filledAttestationData;
    private final MessageDigest sha256;
    private final TransientStorage transientStorage;
    private BufferManager bufferManager;
    private ResidentKeyData[] residentKeys;
    private short numResidentCredentials;
    private final byte[] aaguid = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    private final Signature attester;



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

    private void sendErrorByte(APDU apdu, byte sendByte) {
        transientStorage.clearOutgoingContinuation();
        bufferManager.clear();
        byte[] buffer = apdu.getBuffer();
        buffer[0] = sendByte;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        throwException(ISO7816.SW_NO_ERROR);
    }

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
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), bufferMem, chainOff, amtRead);
        short curRead = amtRead;
        while (curRead < lc) {
            short read = apdu.receiveBytes((short) 0);
            if (read == 0) {
                throwException(ISO7816.SW_WRONG_LENGTH);
            }
            if (curRead > (short) (bufferMem.length - read)) {
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

    private void loadWrappingKey() {
        lowSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
    }

    /** U2F authenticate requires a provisioned attestation certificate chain. */
    private boolean isU2fProvisioned() {
        return attestationData != null && filledAttestationData >= attestationData.length;
    }

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
            readIdx += optionStrLen;
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        if (requireRK && !transientStorage.hasRKOption()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
        }
        return readIdx;
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

    private void encodeCredentialID(APDU apdu, ECPrivateKey privKey,
            byte[] outBuffer, short outOffset, short rkNum) {
        final short scratchHandle = bufferManager.allocate(apdu, KEY_POINT_LENGTH, BufferManager.ANYWHERE);
        final byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        privKey.getS(scratch, scratchOff);
        random.generateData(outBuffer, outOffset, IV_LEN);
        short payloadOffset = (short) (outOffset + IV_LEN);
        // Payload is exactly the private key scalar: no RP ID hash, no marker block.
        payloadOffset = Util.arrayCopyNonAtomic(scratch, scratchOff, outBuffer, payloadOffset, KEY_POINT_LENGTH);
        symmetricWrapper.init(lowSecurityWrappingKey, Cipher.MODE_ENCRYPT, outBuffer, outOffset, IV_LEN);
        final short encryptedBytes = symmetricWrapper.doFinal(outBuffer, (short) (outOffset + IV_LEN),
                CREDENTIAL_PAYLOAD_LEN, outBuffer, (short) (outOffset + IV_LEN));
        // Authenticate the entire IV + ciphertext (encrypt-then-MAC).
        hmacSha256(apdu, credentialVerificationKey, (short) 0,
                outBuffer, outOffset, (short) (CREDENTIAL_PAYLOAD_LEN + IV_LEN),
                scratch, scratchOff);
        Util.arrayCopyNonAtomic(scratch, scratchOff, outBuffer, payloadOffset, (short) 16);
        bufferManager.release(apdu, scratchHandle, KEY_POINT_LENGTH);
        if (encryptedBytes != CREDENTIAL_PAYLOAD_LEN) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }
    }

    private boolean checkCredential(APDU apdu, short rkNum,
            byte[] outputBuffer, short outputOffset) {
        return checkCredential(apdu, residentKeys[rkNum].getEncryptedCredentialID(), (short) 0,
                residentKeys[rkNum].getCredLen(), outputBuffer, outputOffset);
    }

    private boolean checkCredential(APDU apdu, byte[] credentialBuffer, short credentialOffset, short credentialLen,
            byte[] outputBuffer, short outputOffset) {
        final short scratchHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final byte[] scratch = bufferManager.getBufferForHandle(apdu, scratchHandle);
        final short scratchOff = bufferManager.getOffsetForHandle(scratchHandle);
        try {
            Util.arrayFillNonAtomic(scratch, scratchOff, CREDENTIAL_ID_LEN, (byte) 0);
            if (credentialLen == CREDENTIAL_ID_LEN) {
                Util.arrayCopyNonAtomic(credentialBuffer, credentialOffset,
                        scratch, scratchOff, CREDENTIAL_ID_LEN);
            }
            hmacSha256(apdu, credentialVerificationKey, (short) 0,
                    scratch, scratchOff, (short) (CREDENTIAL_PAYLOAD_LEN + IV_LEN),
                    outputBuffer, outputOffset);
            final boolean tagOk = SecureCompare.eq(scratch, (short) (scratchOff + CREDENTIAL_ID_LEN - 16),
                    outputBuffer, outputOffset, (short) 16);
            // Decrypt the payload (the private key scalar) into the output buffer for the caller.
            extractCredentialMixed(scratch, scratchOff, outputBuffer, outputOffset);
            // RP ID check intentionally skipped: we accept our resident credential for any requested
            // RP ID. Authenticity rests entirely on the HMAC tag (tagOk) over the IV + ciphertext.
            return credentialLen == CREDENTIAL_ID_LEN && tagOk;
        } finally {
            bufferManager.release(apdu, scratchHandle, CREDENTIAL_ID_LEN);
        }
    }

    private void resetWrappingKeys(APDU apdu) {
        random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
        lowSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
        random.generateData(wrappingKeyValidation, (short) 0, (short) 32);
        hmacSha256(apdu, wrappingKeySpace, (short) 0,
                wrappingKeyValidation, (short) 0, (short) 32,
                wrappingKeyValidation, (short) 32);
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
                while (!streamOutgoingContinuation(apdu, apduBytes, false)) ;
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
        if (apdu.getIncomingLength() < AID.length || Util.arrayCompare(AID, (short) 0,
                apdu.getBuffer(), apdu.getOffsetCdata(), (short) AID.length) != 0) {
            throwException(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (bufferManager == null) {
            initTransientStorage(apdu);
            short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            final short transientMem = availableMem >= MAX_RAM_SCRATCH_SIZE ? MAX_RAM_SCRATCH_SIZE : availableMem;
            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                bufferManager = new BufferManager(transientMem, FLASH_SCRATCH_SIZE);
                bufferManager.initializeAPDU(apdu);
                resetWrappingKeys(apdu);
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
        random.generateData(credentialVerificationKey, (short) 0, (short) credentialVerificationKey.length);
    }

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

    /**
     * Pushes the credential's private key and compressed public key to NdefApplet via
     * {@link NdefKeyStore}. After this call NdefApplet signs URLs independently.
     *
     * @return true if the key was pushed and committed; false if NDEF is unavailable or push failed
     */
    private boolean pushKeyToNdefApplet() {
        if (numResidentCredentials == 0 || residentKeys[0] == null) {
            return false;
        }
        try {
            loadWrappingKey();
            extractCredentialMixed(residentKeys[0].getEncryptedCredentialID(), (short) 0,
                    ndefPushScratch, (short) 0);
            residentKeys[0].unpackPublicKey(ndefPushScratch, (short) 144);

            AID ndefAid = JCSystem.lookupAID(NDEF_CLIENT_AID, (short) 0,
                    (byte) NDEF_CLIENT_AID.length);
            if (ndefAid == null) {
                return false;
            }
            Shareable s = JCSystem.getAppletShareableInterfaceObject(
                    ndefAid, NdefKeyStore.SERVICE_ID);
            if (!(s instanceof NdefKeyStore)) {
                return false;
            }
            NdefKeyStore ks = (NdefKeyStore) s;

            for (short i = 0; i < KEY_POINT_LENGTH; i++) {
                ks.setPrivKeyByte(i, ndefPushScratch[i]);
            }
            for (short i = 0; i < COMPRESSED_PUBKEY_LEN; i++) {
                ks.setPubKeyByte(i, ndefPushScratch[(short) (144 + i)]);
            }
            ks.commit();
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            Util.arrayFillNonAtomic(ndefPushScratch, (short) 0, NDEF_PUSH_SCRATCH_SIZE, (byte) 0);
        }
    }

    private void makeCredential(APDU apdu, short lc, byte[] buffer) {
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
        final short userIdIdx = transientStorage.getStoredIdx();
        final byte userIdLen = transientStorage.getStoredLen();
        if (userIdLen > MAX_USER_ID_LENGTH) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_REQUEST_TOO_LARGE);
        }
        final short userNameIdx = transientStorage.getStoredIdx2();
        final byte userNameLen = transientStorage.getStoredLen2();
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
                default:
                    break;
            }
            if (readIdx >= lc) {
                sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_CBOR);
            }
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        if (!transientStorage.hasRKOption()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INVALID_OPTION);
        }
        loadWrappingKey();
        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.ANYWHERE);
        final short scratchRPIDHashOffset = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashOffset);
        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);
        if (numResidentCredentials > 0 && residentKeys[0] != null) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_LIMIT_EXCEEDED);
        }
        P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
        final short scratchPublicKeyHandle = bufferManager.allocate(apdu, PUB_KEY_LENGTH, BufferManager.ANYWHERE);
        final short scratchPublicKeyOffset = bufferManager.getOffsetForHandle(scratchPublicKeyHandle);
        final byte[] scratchPublicKeyBuffer = bufferManager.getBufferForHandle(apdu, scratchPublicKeyHandle);
        if (!makeGoodKeyPair(ecKeyPair, scratchPublicKeyBuffer, scratchPublicKeyOffset)) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_INTEGRITY_FAILURE);
        }
        final short scratchUserIdHandle = bufferManager.allocate(apdu, MAX_USER_ID_LENGTH, BufferManager.ANYWHERE);
        final short scratchUserIdOffset = bufferManager.getOffsetForHandle(scratchUserIdHandle);
        final byte[] scratchUserIdBuffer = bufferManager.getBufferForHandle(apdu, scratchUserIdHandle);
        Util.arrayCopyNonAtomic(buffer, userIdIdx, scratchUserIdBuffer, scratchUserIdOffset, userIdLen);
        if (userIdLen < MAX_USER_ID_LENGTH) {
            Util.arrayFillNonAtomic(scratchUserIdBuffer, (short) (scratchUserIdOffset + userIdLen),
                    (short) (MAX_USER_ID_LENGTH - userIdLen), (byte) 0x00);
        }
        encodeCredentialID(apdu, (ECPrivateKey) ecKeyPair.getPrivate(),
                scratchCredBuffer, scratchCredOffset, (short) 0);
        JCSystem.beginTransaction();
        boolean ok = false;
        try {
            numResidentCredentials = 1;
            compressSecp256r1PublicKey(scratchPublicKeyBuffer, (short) (scratchPublicKeyOffset + 1),
                    scratchPublicKeyBuffer, scratchPublicKeyOffset);
            residentKeys[0] = new ResidentKeyData(random, lowSecurityWrappingKey, symmetricWrapper,
                    scratchPublicKeyBuffer, scratchPublicKeyOffset, COMPRESSED_PUBKEY_LEN);
            residentKeys[0].setEncryptedCredential(scratchCredBuffer, scratchCredOffset, CREDENTIAL_ID_LEN);
            residentKeys[0].setUser(lowSecurityWrappingKey, symmetricWrapper,
                    scratchUserIdBuffer, scratchUserIdOffset, userIdLen,
                    buffer, userNameIdx, userNameLen);
            bufferManager.release(apdu, scratchUserIdHandle, MAX_USER_ID_LENGTH);
            final short scratchResidentRPIDHandle = bufferManager.allocate(apdu, MAX_RESIDENT_RP_ID_LENGTH,
                    BufferManager.ANYWHERE);
            final short scratchResidentRPIDOffset = bufferManager.getOffsetForHandle(scratchResidentRPIDHandle);
            final byte[] scratchResidentRPIdBuffer = bufferManager.getBufferForHandle(apdu, scratchResidentRPIDHandle);
            rpIdLen = truncateRPId(buffer, rpIdIdx, rpIdLen, scratchResidentRPIdBuffer, scratchResidentRPIDOffset);
            residentKeys[0].setRpId(lowSecurityWrappingKey, symmetricWrapper,
                    scratchResidentRPIdBuffer, scratchResidentRPIDOffset, (byte) rpIdLen);
            bufferManager.release(apdu, scratchResidentRPIDHandle, MAX_RESIDENT_RP_ID_LENGTH);
            ok = true;
        } catch (Exception e) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
        } finally {
            if (ok) {
                JCSystem.commitTransaction();
            } else {
                JCSystem.abortTransaction();
            }
        }
        final short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, BufferManager.ANYWHERE);
        final short clientDataHashScratchOffset = bufferManager.getOffsetForHandle(clientDataHashHandle);
        final byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        Util.arrayCopyNonAtomic(buffer, clientDataHashIdx, clientDataHashBuffer, clientDataHashScratchOffset,
                CLIENT_DATA_HASH_LEN);
        short outputLen = 0;
        bufferMem[outputLen++] = 0x00;
        bufferMem[outputLen++] = (byte) 0xA3;
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
            attester.init(ecKeyPair.getPrivate(), Signature.MODE_SIGN);
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
        // Push signing key to NdefApplet while FIDO2 is still selected so AES works.
        // After this, NdefApplet signs URLs independently on every NFC read.
        if (!pushKeyToNdefApplet()) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_KEY_STORE_FULL);
        }
        doSendResponse(apdu, outputLen);
    }


    private void getAssertion(final APDU apdu, final short lc, final byte[] buffer) {
        short readIdx = 1;
        final short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, BufferManager.NOT_APDU_BUFFER);
        final byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        final short scratchRPIDHashIdx = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        final short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, BufferManager.NOT_APDU_BUFFER);
        final byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        final short clientDataHashIdx = bufferManager.getOffsetForHandle(clientDataHashHandle);
        final short credStorageHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, BufferManager.NOT_APDU_BUFFER);
        final short credStorageOffset = bufferManager.getOffsetForHandle(credStorageHandle);
        final byte[] credStorageBuffer = bufferManager.getBufferForHandle(apdu, credStorageHandle);
        short rkMatch = -1;
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
            rpIdLen = buffer[readIdx++];
        } else if (buffer[readIdx] >= 0x61 && buffer[readIdx] < 0x78) {
            rpIdLen = (short) (buffer[readIdx] - 0x60);
            readIdx++;
        } else {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return;
        }
        final short rpIdIdx = readIdx;
        readIdx += rpIdLen;
        if (buffer[readIdx++] != 0x02) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (buffer[readIdx++] != 0x58 || buffer[readIdx++] != CLIENT_DATA_HASH_LEN) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
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
                default:
                    break;
            }
            readIdx = skipCborValue(apdu, buffer, readIdx, lc);
        }
        loadWrappingKey();
        if (numResidentCredentials > 0 && residentKeys[0] != null) {
            short credTempHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN, BufferManager.ANYWHERE);
            short credTempOffset = bufferManager.getOffsetForHandle(credTempHandle);
            byte[] credTempBuffer = bufferManager.getBufferForHandle(apdu, credTempHandle);
            if (checkCredential(apdu, (short) 0,
                    credTempBuffer, credTempOffset)) {
                rkMatch = 0;
                loadScratchIntoAttester(credTempBuffer, credTempOffset);
                Util.arrayCopyNonAtomic(residentKeys[0].getEncryptedCredentialID(), (short) 0,
                        credStorageBuffer, credStorageOffset, residentKeys[0].getCredLen());
            }
            bufferManager.release(apdu, credTempHandle, CREDENTIAL_PAYLOAD_LEN);
        }
        if (rkMatch < 0) {
            sendErrorByte(apdu, FIDOConstants.CTAP2_ERR_NO_CREDENTIALS);
        }
        byte[] outputBuffer = bufferMem;
        short outputIdx = 0;
        outputBuffer[outputIdx++] = FIDOConstants.CTAP2_OK;
        byte numMapEntries = (byte) (rkMatch > -1 ? 0xA4 : 0xA3);
        outputBuffer[outputIdx++] = numMapEntries;
        outputBuffer[outputIdx++] = 0x01;
        outputIdx = packCredentialId(credStorageBuffer, credStorageOffset, outputBuffer, outputIdx);
        outputBuffer[outputIdx++] = 0x02;
        byte flags = 0x01; // UP (user present)
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
        if (rkMatch > -1) {
            final short uidLen = residentKeys[rkMatch].getUserIdLength();
            outputBuffer[outputIdx++] = 0x04;
            outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.SINGLE_ID_MAP_PREAMBLE, (short) 0,
                    outputBuffer, outputIdx, (short) CannedCBOR.SINGLE_ID_MAP_PREAMBLE.length);
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, uidLen, true);
            residentKeys[rkMatch].unpackUserID(lowSecurityWrappingKey, symmetricUnwrapper, outputBuffer, outputIdx);
            outputIdx += uidLen;
        }
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
/**
     * Copies a section of a raw RP ID into a target buffer. If it is longer than
     * the max it will be cut down.
     * If it is shorter, it will be zero-padded.
     *
     * @param rpIdBuf    Buffer containing the raw RP ID
     * @param rpIdIdx    Index of RP ID in the incoming buffer
     * @param rpIdLen    Length of the incoming RP ID
     * @param outputBuff Output buffer into which to write truncated/padded values
     * @param outputOff  Write index into output buffer
     *
     * @return Length of RP ID after padding/truncation
     */
    private short truncateRPId(byte[] rpIdBuf, short rpIdIdx, short rpIdLen, byte[] outputBuff, short outputOff) {
        if (rpIdLen <= MAX_RESIDENT_RP_ID_LENGTH) {
            Util.arrayCopyNonAtomic(rpIdBuf, rpIdIdx,
                    outputBuff, outputOff, rpIdLen);
        } else {
            // Truncation necessary...
            short colonPos = -1;
            for (short i = 0; i < rpIdLen; i++) {
                if (rpIdBuf[(short) (rpIdIdx + i)] == (byte) ':') {
                    colonPos = i;
                    break;
                }
            }
            short used = 0;

            if (colonPos != -1) {
                short protocolLen = (short) (colonPos + 1);
                short toCopy = protocolLen <= MAX_RESIDENT_RP_ID_LENGTH ? protocolLen : MAX_RESIDENT_RP_ID_LENGTH;

                Util.arrayCopyNonAtomic(rpIdBuf, rpIdIdx,
                        outputBuff, outputOff, toCopy);

                used += toCopy;
            }

            if ((short) (MAX_RESIDENT_RP_ID_LENGTH - used) < 3) {
                // No room for anything but the protocol bit we already copied
                rpIdLen = used;
            } else {
                // Insert ellipsis
                outputBuff[(short) (outputOff + used++)] = (byte) 0xE2;
                outputBuff[(short) (outputOff + used++)] = (byte) 0x80;
                outputBuff[(short) (outputOff + used++)] = (byte) 0xA6;

                // Copy anything else we have room for after the ellipsis
                short toCopy = (short) (MAX_RESIDENT_RP_ID_LENGTH - used);
                Util.arrayCopyNonAtomic(rpIdBuf, (short) (rpIdIdx + used),
                        outputBuff, (short) (outputOff + used), toCopy);
                rpIdLen = MAX_RESIDENT_RP_ID_LENGTH;
            }
        }

        if (rpIdLen < MAX_RESIDENT_RP_ID_LENGTH) {
            // Zero-fill remainder after RP ID
            Util.arrayFillNonAtomic(outputBuff, (short) (outputOff + rpIdLen),
                    (short) (MAX_RESIDENT_RP_ID_LENGTH - rpIdLen), (byte) 0x00);
        }

        return rpIdLen;
    }
/**
     * Hand-spun implementation of HMAC-SHA256, to work around lack of hardware
     * support
     *
     * @param apdu       Request/response object
     * @param keyBuff    Buffer containing 32-byte-long private key
     * @param keyOff     Offset of private key in key buffer
     * @param content    Buffer containing arbitrary-length content to be HMACed
     * @param contentOff Offset of content in buffer
     * @param contentLen Length of content
     * @param outputBuff Buffer into which output should be written - must have 32
     *                   bytes available
     * @param outputOff  Write index into output buffer
     */
    private void hmacSha256(APDU apdu, byte[] keyBuff, short keyOff,
            byte[] content, short contentOff, short contentLen,
            byte[] outputBuff, short outputOff) {
        final short scratchAmt = (short) ((contentLen < 32 ? 32 : contentLen) + 64);
        short scratchHandle = bufferManager.allocate(apdu, scratchAmt, BufferManager.ANYWHERE);
        byte[] workingBuffer = bufferManager.getBufferForHandle(apdu, scratchHandle);
        short workingFirst = bufferManager.getOffsetForHandle(scratchHandle);
        short workingSecond = (short) (workingFirst + 32);
        short workingMessage = (short) (workingSecond + 32);

        // first half: put key + 32x 0x36 + content into the buffer
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short) (i + keyOff)] ^ (0x36)); // ipad
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x36);

        Util.arrayCopyNonAtomic(content, contentOff,
                workingBuffer, workingMessage, contentLen);

        sha256.doFinal(workingBuffer, workingFirst, (short) (64 + contentLen),
                workingBuffer, workingMessage);

        // second half: put key + 32x 0x5c into buffer, then hash into spot adjacent to
        // previous hash
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short) (i + keyOff)] ^ (0x5c)); // opad
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x5c);

        sha256.doFinal(workingBuffer, workingFirst, (short) 96, outputBuff, outputOff);

        bufferManager.release(apdu, scratchHandle, scratchAmt);
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
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
        }
        return readIdx;
    }

    private short readUserMap(APDU apdu, byte[] buffer, short readIdx, short lc) {
        transientStorage.readyStoredVars();
        transientStorage.setStoredVars2((short) 0, (byte) 0);
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
            final boolean isName = (keyLen == 4 && buffer[keyIdx] == 'n' && buffer[(short) (keyIdx + 1)] == 'a'
                    && buffer[(short) (keyIdx + 2)] == 'm' && buffer[(short) (keyIdx + 3)] == 'e');
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
            } else if (isName && valDef >= 0x0060 && valDef <= 0x0078) {
                transientStorage.setStoredVars2(valStart, (byte) valLen);
            }
        }

        if (!foundId) {
            sendErrorByte(apdu, FIDOConstants.CTAP1_ERR_INVALID_PARAMETER);
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
/**
     * Initializes the attester with a given key. After call, attestations may be
     * made.
     *
     * @param buffer Buffer containing 32 bytes of key data
     * @param offset Offset into given buffer of key's first byte
     */
    private void loadScratchIntoAttester(byte[] buffer, short offset) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        P256Constants.setCurve(ecPrivateKey);
        ecPrivateKey.setS(buffer, offset, (short) 32);
        attester.init(ecPrivateKey, Signature.MODE_SIGN);
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

    private void extractCredentialMixed(byte[] credentialBuffer, short credentialOffset,
            byte[] outputBuffer, short outputOffset) {
        symmetricUnwrapper.init(lowSecurityWrappingKey, Cipher.MODE_DECRYPT, credentialBuffer, credentialOffset, IV_LEN);
        final short ret = symmetricUnwrapper.doFinal(credentialBuffer, (short) (credentialOffset + IV_LEN),
                CREDENTIAL_PAYLOAD_LEN, outputBuffer, outputOffset);
        if (ret != CREDENTIAL_PAYLOAD_LEN) {
            throwException(ISO7816.SW_DATA_INVALID);
        }
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
     * Pack a credential ID (CBOR-wrapped) into a target buffer
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
     * Gets an elliptic curve private key object.
     *
     * @param forceAllowTransient If true, allow this PRIVATE key to be in transient
     *                            memory
     * @param allowDeselectMemory If true, allow this key to be cleared on applet
     *                            deselect - unusual for private keys...
     * @return An uninitialized EC private key, ideally in RAM, but in flash if the
     *         authenticator doesn't support in-memory
     */
    private ECPrivateKey getECPrivKey(boolean forceAllowTransient, boolean allowDeselectMemory) {
        if (forceAllowTransient) {
            if (allowDeselectMemory) {
                try {
                    return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                            KeyBuilder.LENGTH_EC_FP_256, false);
                } catch (CryptoException e) {
                    // Oh well, unsupported, use normal RAM or flash instead
                }
            }

            try {
                return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET,
                        KeyBuilder.LENGTH_EC_FP_256, false);
            } catch (CryptoException e) {
                // Oh well, unsupported, use flash instead
            }
        }

        return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }
/**
     * Get a persistent AES key
     *
     * @return An AESKey object that will retain its contents indefinitely
     */
    private AESKey getPersistentAESKey() {
        return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }
/**
     * Gets AES encipherment
     *
     * @return A Cipher set up for AES with an authenticator-supported block size
     */
    private Cipher getAES() {
        // NB: a 128-bit block size is used even for AES256. Just because this says
        // "128"
        // doesn't say anything about the key length
        return Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
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

        // Yuck.
        return new byte[len];
    }
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
            // Too late!
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
                // These bytes should/must be a CBOR array
                // it's doubtful trying to use >15 certificates is a good idea, either
                throwException(ISO7816.SW_DATA_INVALID);
            }

            attestationData = new byte[expectedLength];
            filledAttestationData = amountToRead;
            Util.arrayCopy(params, offset,
                    attestationData, (short) 0, amountToRead);

            if (filledAttestationData == attestationData.length) {
                // Done!
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
                // Loaded up, ready to go, locked
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
        // RAM usage - (ideally) ephemeral keys
        ecKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey(ecPairInRam, false));
        P256Constants.setCurve((ECKey) ecKeyPair.getPrivate());
        P256Constants.setCurve((ECKey) ecKeyPair.getPublic());
    }
    private void compressSecp256r1PublicKey(byte[] xy, short xyOff, byte[] out, short outOff) {
        out[outOff] = (byte) (0x02 | (xy[(short) (xyOff + 63)] & 1));
        Util.arrayCopyNonAtomic(xy, xyOff, out, (short) (outOff + 1), (short) 32);
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            handleAppletSelect(apdu);
            return;
        }
        final byte[] apduBytes = apdu.getBuffer();
        final short cla_ins = Util.getShort(apduBytes, ISO7816.OFFSET_CLA);
        final short p1_p2 = Util.getShort(apduBytes, ISO7816.OFFSET_P1);
        if (cla_ins == (short) 0x8012 && p1_p2 == (short) 0x0100) {
            transientStorage.disableAuthenticator();
        }
        if (cla_ins == (short) 0x00A4 && p1_p2 == (short) 0x0400) {
            handleAppletSelect(apdu);
            return;
        }
        if (transientStorage.authenticatorDisabled()) {
            return;
        }
        if (cla_ins == 0x00C0 || cla_ins == (short) 0x80C0) {
            streamOutgoingContinuation(apdu, apduBytes, true);
            return;
        } else {
            transientStorage.clearOutgoingContinuation();
        }
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
        
        if (cla_ins == 0x0001) {
            transientStorage.clearOutgoingContinuation();
            // Single resident-key slot is full; U2F clients only handle ISO7816 SW codes.
            throwException(ISO7816.SW_FILE_FULL);
            return;
        }else if (cla_ins == 0x0002) {
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

    public void deselect() {
        transientStorage.clearOnDeselect();
    }

     private void u2FAuthenticate(APDU apdu, byte p1) {
        if (!isU2fProvisioned()) {
            // Authenticating requires an attestation certificate!
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

        if (numResidentCredentials == 0 || residentKeys[0] == null) {
            throwException(ISO7816.SW_WRONG_DATA);
        }

        final short scratchCredHandle = bufferManager.allocate(apdu, CREDENTIAL_PAYLOAD_LEN,
                BufferManager.NOT_APDU_BUFFER);
        final short scratchCredOffset = bufferManager.getOffsetForHandle(scratchCredHandle);
        final byte[] scratchCredBuffer = bufferManager.getBufferForHandle(apdu, scratchCredHandle);

        loadWrappingKey();
        if (!checkCredential(apdu, (short) 0, scratchCredBuffer, scratchCredOffset)) {
            bufferManager.release(apdu, scratchCredHandle, CREDENTIAL_PAYLOAD_LEN);
            throwException(ISO7816.SW_WRONG_DATA);
        }

        if (p1 == 0x07) {
            // Check-only: key handle accepted, no signature (U2F spec §4.2).
            bufferManager.release(apdu, scratchCredHandle, CREDENTIAL_PAYLOAD_LEN);
            sendNoCopy(apdu, (short) 0);
            return;
        }

        loadScratchIntoAttester(scratchCredBuffer, scratchCredOffset);

        final byte flag_byte = 0x01; // User always present

        final short scratchSigHandle = bufferManager.allocate(apdu,
                (short) (RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5), BufferManager.NOT_APDU_BUFFER);
        final short scratchSigOffset = bufferManager.getOffsetForHandle(scratchSigHandle);
        final byte[] scratchSigBuffer = bufferManager.getBufferForHandle(apdu, scratchSigHandle);

        random.generateData(scratchSigBuffer, scratchSigOffset, (short) 1);
        counter.increment((short) ((scratchSigBuffer[scratchSigOffset] & 0x0E) + 1));

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
        bufferManager.release(apdu, scratchCredHandle, CREDENTIAL_PAYLOAD_LEN);
        bufferManager.release(apdu, scratchSigHandle,
                (short) (RP_HASH_LEN + CLIENT_DATA_HASH_LEN + 5));
        sendNoCopy(apdu, (short) (sigLen + 5));
    }


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

    private FIDO2Applet(byte[] array, short offset, byte length) {
        attestationSwitchingEnabled = false;
        MAX_RESIDENT_RP_ID_LENGTH = 32;
        // Defaults favor RAM-first operation; flash fallback (bufferMem / flashBuffer) causes
        // EEPROM wear when CTAP scratch exhausts transient space. Tune down only after testAll
        // passes with your attestation chain size (see tools/get_install_parameters.py).
        MAX_RAM_SCRATCH_SIZE = 512;
        BUFFER_MEM_SIZE = 2048;
        FLASH_SCRATCH_SIZE = 1024;
        final short initOffset = offset;
        if (length > 0) {
            short sb = ub(array[offset++]);
            short numOptions = (short) (sb - 0xA0);
            for (; numOptions > 0; numOptions--) {
                if (offset > (short) (length + initOffset - 1)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                switch (array[offset++]) {
                    case 0x00:
                        attestationSwitchingEnabled = array[offset++] == (byte) 0xF5;
                        break;
                    case 0x09:
                        if (array[offset] == 0x18) {
                            offset++;
                            MAX_RAM_SCRATCH_SIZE = ub(array[offset++]);
                        } else if (array[offset] == 0x19) {
                            offset += 3;
                            MAX_RAM_SCRATCH_SIZE = Util.getShort(array, (short) (offset - 2));
                        } else {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        break;
                    case 0x0A:
                        if (array[offset++] != 0x19) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        BUFFER_MEM_SIZE = Util.getShort(array, offset);
                        offset += 2;
                        break;
                    case 0x0B:
                        if (array[offset] == 0x18) {
                            offset++;
                            FLASH_SCRATCH_SIZE = ub(array[offset++]);
                        } else if (array[offset] == 0x19) {
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
        wrappingKeySpace = new byte[32];
        wrappingKeyValidation = new byte[64];
        credentialVerificationKey = new byte[32];
        lowSecurityWrappingKey = getPersistentAESKey();
        residentKeys = new ResidentKeyData[1];
        numResidentCredentials = 0;
        counter = new SigOpCounter();
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        symmetricWrapper = getAES();
        symmetricUnwrapper = getAES();
        attester = getECSig();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        transientStorage = new TransientStorage();
        initCredKey(true);
        ndefPushScratch = JCSystem.makeTransientByteArray(NDEF_PUSH_SCRATCH_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

}
