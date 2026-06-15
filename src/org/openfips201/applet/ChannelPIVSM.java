package org.openfips201.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/***
 * An implementation of the PIV Secure Messaging channel
 */
final class ChannelPIVSM {

  //
  // Constants
  // 

  private static final byte CLA_MASK_SECURE_MESSAGING = (byte) 0x0C;
  private static final byte CLA_FLAG_PIVSM = (byte) 0x0C;

  //
  // Command Handling State
  //

  // No session is established and no data is being processed
  private static final byte STATE_NONE = (byte) 0;

  // A session is established but not data is being processed
  private static final byte STATE_ESTABLISHED = (byte) 1;

  // A command has been successfully processed and we can now process a response.
  private static final byte STATE_INCOMING_COMPLETE = (byte) 2;

  // A response is processing the outgoing DATA segment
  private static final byte STATE_OUTGOING_DATA = (byte) 3;

  // A response is processing the outgoing STATUS and RMAC trailer bytes  
  private static final byte STATE_OUTGOING_TRAILER = (byte) 4;

  // The previous response wrapping completed successfully  
  private static final byte STATE_OUTGOING_COMPLETE = (byte) 5;

  //
  // Session Constants
  // 
  private static final short SW_SM_DATA_OBJECTS_MISSING = 0x6987;
  private static final short SW_SM_DATA_OBJECTS_INCORRECT = 0x6988;

  private static final byte MAC_PADDING_BYTE = (byte) 0x80;
  private static final byte PADDING_INDICATOR = (byte) 0x01;
  private static final short LENGTH_LE_ENCODED = (short) 3;
  private static final short LENGTH_STATUS_ENCODED = (short) 4; // 9902[SW12]8808[MAC]
  private static final short LENGTH_MAC_ENCODED = (short) 10; // 9902[SW12]8808[MAC]
  private static final short LENGTH_TRAILER_ENCODED = (short) (LENGTH_STATUS_ENCODED + LENGTH_MAC_ENCODED);

  private static final byte TAG_DATA = (byte) 0x87;
  private static final byte TAG_MAC = (byte) 0x8E;
  private static final byte TAG_LE = (byte) 0x97;
  private static final byte TAG_STATUS = (byte) 0x99;

  private static final byte LENGTH_STATUS = (byte) 2;
  private static final short LENGTH_MAC = (short) 8;
  private static final short LENGTH_BLOCK = (short) 16;

  private static final short OFFSET_STATE = (short) 0;
  private static final short OFFSET_ACTIVE_SUITE = (short) 1;
  private static final short OFFSET_CMD_MCV = (short) 2;
  private static final short OFFSET_RSP_MCV = (short) (OFFSET_CMD_MCV + LENGTH_BLOCK);
  private static final short OFFSET_SCRATCH = (short) (OFFSET_RSP_MCV + LENGTH_BLOCK);

  // Convenience function for calling Util.setShort() 
  private static final short OFFSET_SCRATCH_MSB = (short) (OFFSET_SCRATCH + LENGTH_BLOCK - 2);
  private static final short LENGTH_CONTEXT = (short) (3 + LENGTH_BLOCK + LENGTH_BLOCK + LENGTH_BLOCK);

  // Counters to track command/response IV values and data bytes written in the wrapping operation.
  private static final short COUNTER_COMMAND = (short) 0;
  private static final short COUNTER_RESPONSE = (short) 1;
  private static final short COUNTER_LAST_BYTES_WRAPPED = (short) 2;
  private static final short COUNTER_REMAINING_BYTES_WRAPPED = (short) 3;
  private static final short LENGTH_COUNTERS = (short) 4;

  // 
  // Variables
  //

  // PERSISTENT - CSP implementations
  private final Signature cspCMAC;
  private final Cipher cspAES;

  // TRANSIENT - Session processing context
  private final byte[] context;
  private final short[] counters;

  // PERSISTENT - Holds the cipher suite session and algorithm info.  
  private CipherSuite cipherSuite = null;

  ChannelPIVSM() {
    // NOTE: The SP800-73-5pt2 4.3, a session is only cleared on RESET, not DESELECT
    // This is also reflected in the session key creation in the CipherSuite object
    context = JCSystem.makeTransientByteArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_RESET);
    counters = JCSystem.makeTransientShortArray(LENGTH_COUNTERS, JCSystem.CLEAR_ON_RESET);

    // Instantiate Ciphers that are common to both cipher suites.
    cspAES = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
    cspCMAC = Platform.Cryptography.getCMAC();
  }

  boolean isInitialised() {
    return (cipherSuite != null);
  }

  void init(byte mechanism) {
    if (cipherSuite == null) {
      cipherSuite = new CipherSuite(mechanism);
    }
  }

  byte getSupportedMechanism() {
    if (cipherSuite != null) {
      return cipherSuite.MECHANISM_ID;
    } else {
      return 0;
    }
  }

  boolean isEstablished() {
    return context[OFFSET_STATE] != STATE_NONE;
  }

  void reset() {
    if (!isEstablished()) {
      return;
    }

    // Clear any cipher Suites
    cipherSuite.clear();

    // Clear the session context (OFFSET_STATE will become STATE_NONE)
    counters[COUNTER_COMMAND] = 0;
    counters[COUNTER_RESPONSE] = 0;
    counters[COUNTER_REMAINING_BYTES_WRAPPED] = 0;
    counters[COUNTER_LAST_BYTES_WRAPPED] = 0;
    Util.arrayFillNonAtomic(context, Constants.ZERO_SHORT, LENGTH_CONTEXT, Constants.ZERO_BYTE);
  }

  static boolean isWrapped(byte cla) {
    return (cla & CLA_MASK_SECURE_MESSAGING) == CLA_FLAG_PIVSM;
  }

  static boolean isSupportedCommand(byte ins) {
    switch (ins) {
    case OpenFIPS201.INS_PIV_GET_DATA:
    case OpenFIPS201.INS_PIV_VERIFY:
    case OpenFIPS201.INS_PIV_CHANGE_REFERENCE_DATA:
    case OpenFIPS201.INS_PIV_RESET_RETRY_COUNTER:
    case OpenFIPS201.INS_PIV_GENERAL_AUTHENTICATE:
      return true;
    default:
      return false;
    }
  }

  /***
   * Initialises a new Opacity session using the session keys associated with a PIVKeySM object.
   * @param key The PIVKeySM object
   */
  short establish(PIVKeySM key, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    //
    // CONSTANTS
    //
    final short LENGTH_CBH = (short) 1;
    final short LENGTH_CBICC = (short) 1;
    final short LENGTH_IDSH = (short) 8;
    final short LENGTH_QEH_T16 = (short) 16;

    // We expect the public point to be sent with the uncompressed indicator 04, but we don't use it
    final short LENGTH_QEH = key.getPublicPointLength();

    // FROM NIST SP800-73-4 4.1.1 H3:
    // > [The client sends]: CBh | IDsH | 04 | QeH
    final short OFFSET_CBH = inOffset;
    final short OFFSET_IDSH = (short) (OFFSET_CBH + LENGTH_CBH);
    final short OFFSET_QEH = (short) (OFFSET_IDSH + LENGTH_IDSH);

    // Always reset the state first
    reset();

    // Reset any existing context

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: We must have been initialised to support a particular mechanism
    if (!isInitialised()) {
      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
    }

    // PRE-CONDITION: The supplied key mechanism must match our supported mechanism
    if (key.getMechanism() != cipherSuite.MECHANISM_ID) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION: The SP800-56 algorithms must pass their respective KAT's prior to operation
    // NOTES: 
    // - Technically this only needs to be run once per reset, but since it will typically be
    //   run once only anyway, we just do it every time.
    // - If either self-test fails, an ISOException with SW_CAST_FAILURE will return, which
    //   must be checked by the caller to induce the correct error and new state.    
    SP80056KDAOneStep.doSelfTests(outBuffer, (short) (inOffset + inLength));
    SP80056KasKc.doSelfTests(cspCMAC, cipherSuite.skCFRM, outBuffer, (short) (inOffset + inLength));

    // PRE-CONDITION: The length of the request must match our expected length
    if (inLength != cipherSuite.LENGTH_REQUEST) {
      ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
    }

    // STEP 2 - Perform the PIV Secure Messaging establishment protocol

    // STEP 2/C2 - Calculate cbICC from cbH
    byte cbH = inBuffer[OFFSET_CBH];
    byte cbICC = (byte) (cbH & (byte) 0xF0);

    // STEP 2/C3 - Check that CBicc is 0x00
    if (cbICC != 0x00) {
      ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
    }

    // STEP 2/C4 - Verify that QeH is a valid public key for the domain parameters
    // of QsICC
    // NOTE: This is checked by any FIPS 140-3 compliant ECDH provider

    // STEP 2/C5 - Compute Z = ECC_CDH (dsICC, QeH)
    short zOffset = (short) (inOffset + inLength);
    short zLength = key.keyEstablish(inBuffer, OFFSET_QEH, LENGTH_QEH, inBuffer, zOffset);

    //
    // Construct PartyUInfo = '08' | IDsH | '01' | cbH | '10' | LEFT(QEH, 16) 
    // NOTE: We use inOffset now to track the construction
    short uOffset = (short) (zOffset + zLength);
    inOffset = uOffset;

    // IDSH
    inBuffer[inOffset++] = (byte) LENGTH_IDSH;
    inOffset = Util.arrayCopyNonAtomic(inBuffer, OFFSET_IDSH, inBuffer, inOffset, LENGTH_IDSH);

    // CBh
    inBuffer[inOffset++] = LENGTH_CBH;
    inBuffer[inOffset++] = cbH;

    // T16(QEH)
    // NOTE: The KDF does not include the '04' uncompressed indicator, so we skip it
    inBuffer[inOffset++] = LENGTH_QEH_T16;
    inOffset = Util.arrayCopyNonAtomic(inBuffer, (short) (OFFSET_QEH + 1), inBuffer, inOffset, LENGTH_QEH_T16);

    short uLength = (short) (inOffset - uOffset);

    //
    // Construct PartyVInfo = '08' | IDsICC | [NONCE_LEN] | NONCE | 01 | CBicc
    // NOTE: inOffset is already at the correct position 

    short vOffset = inOffset;

    // IDsICC (We track idsICCOffset for the CMAC later)
    inBuffer[inOffset++] = PIVKeySM.LENGTH_CVC_HASH;
    short idsICCOffset = inOffset;
    inOffset = key.getCvcHash(inBuffer, idsICCOffset);

    // nICC (Nonce)
    // STEP 2/C6 - Generate nonce NICC
    // NOTE: Since the NICC value is needed for the response, we will need to copy this later
    inBuffer[inOffset++] = cipherSuite.LENGTH_NICC;
    short niccOffset = inOffset;
    inOffset = Platform.Cryptography.generateRandom(inBuffer, niccOffset, cipherSuite.LENGTH_NICC);
    inBuffer[inOffset++] = LENGTH_CBICC;
    inBuffer[inOffset++] = cbICC;

    short vLength = (short) (inOffset - vOffset);

    // STEP 2/C7 - SKCFRM | SKMAC | SKENC | SKRMAC = KDF (Z, len, Otherinfo) 
    short dkmOffset = inOffset;
    short dkmLength = SP80056KDAOneStep.doFinal(cipherSuite.HASH_ALGORITHM, inBuffer, zOffset, zLength,
        uOffset, uLength, vOffset, vLength, inBuffer, dkmOffset, cipherSuite.LENGTH_DKM);

    // NOTE: Here we also set and then zeroise the other session key data
    cipherSuite.skCFRM.setKey(inBuffer, inOffset);
    inOffset += cipherSuite.LENGTH_AES_KEY_BYTES;
    cipherSuite.skMAC.setKey(inBuffer, inOffset);
    inOffset += cipherSuite.LENGTH_AES_KEY_BYTES;
    cipherSuite.skENC.setKey(inBuffer, inOffset);
    inOffset += cipherSuite.LENGTH_AES_KEY_BYTES;
    cipherSuite.skRMAC.setKey(inBuffer, inOffset);

    // STEP 2/C8 - Zeroize Z
    // NOTE: We get rid of all DKM now since it is set in our session key values 
    Platform.zeroise(inBuffer, zOffset, zLength);
    Platform.zeroise(inBuffer, dkmOffset, dkmLength);

    //
    // STEP 2/C9 - AuthCryptogramICC = CMAC(SKCFRM, "KC_1_V" | IDsICC | IDsH | QeH)
    // NOTE:
    // - We construct the final output before the CMAC so it is where it needs to be
    //   without additional copies.

    // cbICC
    outBuffer[outOffset++] = cbICC;

    // nICC 
    // NOTE: We write this AFTER the CMAC is calculated to avoid clobbering input data

    // authCryptogramICC
    // NOTE: The KDF does not include the '04' uncompressed indicator, so we skip it
    short kcLength = SP80056KasKc.doFinal(cspCMAC, cipherSuite.skCFRM, inBuffer, idsICCOffset, PIVKeySM.LENGTH_CVC_HASH,
        OFFSET_IDSH, LENGTH_IDSH, (short) (OFFSET_QEH + 1), (short) (LENGTH_QEH - 1), inBuffer,
        (short) (outOffset + cipherSuite.LENGTH_NICC));

    // Now we actually write nICC as the outOffset hasn't changed
    outOffset = Util.arrayCopyNonAtomic(inBuffer, niccOffset, outBuffer, outOffset, cipherSuite.LENGTH_NICC);

    //
    // STEP 2/C10 - Zeroize SKCFRM
    cipherSuite.skCFRM.clearKey();

    // STEP 2/C11 - Return cbICC | nICC | AuthCryptogramICC | cICC 

    // Move outOffset past the CMAC, ready to copy CICC
    outOffset += kcLength;

    short cvcLength = key.getCvc(outBuffer, outOffset);

    //
    // DONE
    // 

    // Set our state
    context[OFFSET_ACTIVE_SUITE] = key.getMechanism();
    context[OFFSET_STATE] = STATE_ESTABLISHED;

    // Return the length of all returned elements
    return (short) (cipherSuite.LENGTH_RESPONSE + cvcLength);
  }

  short unwrap(PIVAPDU pApdu) {

    final short NOT_PRESENT = (short) -1;

    byte[] buffer = pApdu.getData();
    short length = pApdu.getDataLength();
    TLVReader reader = TLVReader.getInstance(buffer, pApdu.getDataOffset(), length);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: The supplied APDU must indicate that it is PIV-SM wrapped
    // NOTE: If it does not indicate this, we just return as this is not an error
    if ((pApdu.getCLA() & CLA_MASK_SECURE_MESSAGING) != CLA_FLAG_PIVSM) {
      // There has been no change to the length
      return pApdu.getDataLength();
    }
    // PRE-CONDITION: A session must be established and in one of the correct states
    if (context[OFFSET_STATE] != STATE_ESTABLISHED && context[OFFSET_STATE] != STATE_OUTGOING_COMPLETE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION: The Command and Response counters must match
    // NOTE: This ensures that any unhandled exceptions cause the session to be reset
    if (counters[COUNTER_COMMAND] != counters[COUNTER_RESPONSE]) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION: Padding+Data MAY be present
    short offsetDataTLV = NOT_PRESENT;
    short offsetData = NOT_PRESENT; // Default to not present
    short lengthData = 0;
    short lengthDataTLV = 0;

    if (reader.match(TAG_DATA)) {
      offsetDataTLV = reader.getOffset();
      offsetData = reader.getDataOffset();
      lengthData = reader.getLength();
      lengthDataTLV = (short) (offsetData - offsetDataTLV + lengthData);
      // PRE-CONDITION: If Data is present, the Padding Indicator byte MUST be 01
      if (buffer[offsetData] != PADDING_INDICATOR) {
        ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
      }

      reader.moveNext();
    }

    // PRE-CONDITION: The LE element MAY be present     
    short offsetLE = NOT_PRESENT;
    if (reader.match(TAG_LE)) {
      offsetLE = reader.getOffset();

      // PRE-CONDITION: If present, the LE element must be a single byte and have value '00'
      // NOTE: The static value is specified in SP800-73-5-pt2 4.2.3-4
      if (reader.getLength() != TLV.LENGTH_1BYTE || reader.toByte() != Constants.ZERO_BYTE) {
        ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
      }

      // We don't actually care about the value, since it is static 
      reader.moveNext();
    }

    // PRE-CONDITION: The MAC element must be present    
    if (!reader.match(TAG_MAC)) {
      ISOException.throwIt(SW_SM_DATA_OBJECTS_MISSING);
    }

    // PRE-CONDITION: The MAC element must be of length 8
    if (reader.getLength() != LENGTH_MAC) {
      ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
    }
    short offsetMAC = reader.getDataOffset();

    // PRE-CONDITION: The MAC must successfully validate
    // NOTE: You would normally use MODE_VERIFY here, but you cannot call Signature.verify() when
    // you only have a partial output CMAC. Since the PIVSM specification only contains the first
    // 8 bytes, we have to use MODE_SIGN and compare the result ourselves.
    cspCMAC.init(cipherSuite.skMAC, Signature.MODE_SIGN);

    // CMAC CONSTRUCTION:
    // MCV|HEADER|[eDATA]|[LE]
    // OPTIONAL: 87(LCC+1)01eDATA
    // OPTIONAL: 9701LE

    //
    // 16-byte Mac Chaining Value
    cspCMAC.update(context, OFFSET_CMD_MCV, LENGTH_BLOCK);

    //
    // Construct the header block with ISO 9797 M2 padding
    // HEADER = CLA|INS|P1|P2|800000000000000000000000
    Util.arrayFillNonAtomic(context, OFFSET_SCRATCH, LENGTH_BLOCK, Constants.ZERO_BYTE);
    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CLA, context, OFFSET_SCRATCH, PIVAPDU.LENGTH_HEADER);
    context[(short) (OFFSET_SCRATCH + PIVAPDU.LENGTH_HEADER)] = MAC_PADDING_BYTE;
    cspCMAC.update(context, OFFSET_SCRATCH, LENGTH_BLOCK);

    //
    // eDATA
    if (offsetData != NOT_PRESENT) {
      cspCMAC.update(buffer, offsetDataTLV, lengthDataTLV);
    }

    //
    // LE
    if (offsetLE != NOT_PRESENT) {
      cspCMAC.update(buffer, offsetLE, LENGTH_LE_ENCODED);
    }

    //
    // Compute the CMAC
    // NOTES: 
    // - Since several of the values above are optional, our final call is completed with
    //   a zero-length input.
    // - The result is stored in the CMD_MCV context to be used for the next command unwrap call.
    cspCMAC.sign(buffer, Constants.ZERO_SHORT, Constants.ZERO_SHORT, context, OFFSET_CMD_MCV);

    //
    // Compare the first 8 bytes
    if (Util.arrayCompare(buffer, offsetMAC, context, OFFSET_CMD_MCV, LENGTH_MAC) != 0) {
      ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
    }

    //
    // PRE-CONDITION: With the PADDING_INDICATOR byte removed, the length of the supplied data
    // must be a multiple of the block length.
    //
    // This is checked automatically by the cipher

    //
    // EXECUTION
    //

    // Increment the command counter
    counters[COUNTER_COMMAND]++;

    // Optionally, decrypt the data
    short outLength = 0;
    if (offsetData != NOT_PRESENT) {
      // Skip the Padding Indicator byte
      offsetData++;
      lengthData--;

      // Generate the IV according to SP800-73-5pt2 4.2.2:
      // For command unwrapping, the format is 0000000000000000000000000000nnnn where nnnn is the 
      // command counter.
      Util.arrayFillNonAtomic(context, OFFSET_SCRATCH, LENGTH_BLOCK, Constants.ZERO_BYTE);
      Util.setShort(context, OFFSET_SCRATCH_MSB, counters[COUNTER_COMMAND]);
      Platform.Cryptography.encipher(cipherSuite.skENC, context, OFFSET_SCRATCH, LENGTH_BLOCK, context, OFFSET_SCRATCH);

      //
      // Decrypt the data

      // Initialise the cipher, passing our calculated IV through
      cspAES.init(cipherSuite.skENC, Cipher.MODE_DECRYPT, context, OFFSET_SCRATCH, LENGTH_BLOCK);

      // Decrypt the data, moving it to the beginning of the CDATA section in the PIVAPDU object
      try {
        outLength = cspAES.doFinal(buffer, offsetData, lengthData, buffer, pApdu.getDataOffset());
      } catch (Exception ex) {
        ISOException.throwIt(SW_SM_DATA_OBJECTS_INCORRECT);
      }
    }

    // Done
    context[OFFSET_STATE] = STATE_INCOMING_COMPLETE;
    return outLength;
  }

  /***
   * Wraps response data in PIV Secure Messaging. Handles multi-frame responses.
   * @param inBuffer The input plaintext
   * @param inOffset The offset in the input plaintext
   * @param inLength The remaining length of data to write
   * @param outBuffer
   * @param outOffset
   * @param maxLength
   * @param status
   * @return
   */
  short wrap(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset, short maxLength,
      short status) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: A session must be established
    if (!isEstablished()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION
    //

    // 
    // Each PIV-SM wrapped response is formatted as follows:
    // [eDATA]|STATUS|RMAC
    // WHERE:
    // - eDATA is the encrypted, TLV-encoded data, in the format '87'|LEN(1-3 Bytes)|'01'|DATA (OPTIONAL)
    // - Status is the TLV-encoded status word, in the format 99|02|XXYY
    // - RMAC is the TLV-encoded MAC value, in the format 88|08|AABBCCDDEEFFGGHH
    //
    // NOTES:
    // - We fit as many bytes as we can in each response frame (256 bytes max per frame)
    // - Because the response length is arbitrary, we may run out of buffer space anywhere, 
    //   including in the middle of the DATA, STATUS or RMAC bytes.    
    // - This means that before each subsequent write to the output buffer, we need to check
    //   if it can fit the intended length. If it cannot, we write it to our SCRATCH block.
    //
    // This method is written as a serious of cascading states, with each one running and 
    // progressing to the next when ready, either in the same call or in successive calls to wrap()

    // We track where we have written to and use this to determine the total bytes written
    short offset = outOffset;
    short bytesRemaining = maxLength;

    //
    // STATE_INCOMING_COMPLETE --> STATE_OUTGOING_DATA (At least 1 data byte must be written)
    // STATE_INCOMING_COMPLETE --> STATE_OUTGOING_STATUS (No data to write)
    //
    if (context[OFFSET_STATE] == STATE_INCOMING_COMPLETE) {
      // Initialise our counter to track remaining response bytes
      // NOTE: If there is data we will add to this later
      counters[COUNTER_REMAINING_BYTES_WRAPPED] = LENGTH_TRAILER_ENCODED;

      // Increment the response counter prior to commencing each unwrap
      counters[COUNTER_RESPONSE]++;

      // Initialise the CMAC, passing through the Response MCV first
      cspCMAC.init(cipherSuite.skRMAC, Signature.MODE_SIGN);
      cspCMAC.update(context, OFFSET_RSP_MCV, LENGTH_BLOCK);

      // Begin the eDATA section if required
      if (inLength > 0) {
        // Initialise our Cipher and CMAC providers
        // Generate the IV according to SP800-73-5pt2 4.2.2:
        // For response wrapping, the format is 8000000000000000000000000000nnnn where nnnn is the 
        // response counter.
        Util.arrayFillNonAtomic(context, OFFSET_SCRATCH, LENGTH_BLOCK, Constants.ZERO_BYTE);
        context[OFFSET_SCRATCH] = (byte) 0x80;
        Util.setShort(context, OFFSET_SCRATCH_MSB, counters[COUNTER_RESPONSE]);
        Platform.Cryptography.encipher(cipherSuite.skENC, context, OFFSET_SCRATCH, LENGTH_BLOCK, context,
            OFFSET_SCRATCH);

        // Initialise the Cipher, passing our calculated IV through
        cspAES.init(cipherSuite.skENC, Cipher.MODE_ENCRYPT, context, OFFSET_SCRATCH, LENGTH_BLOCK);

        // Write the TLV header

        // T
        outBuffer[offset++] = TAG_DATA;

        // L (LEN = PaddingIndicator(1) + DataLength + PaddingLength)
        // NOTE: We don't calculate our own padding, we just need to know for the tag length
        short padLength = (short) (LENGTH_BLOCK - (inLength % LENGTH_BLOCK));
        short totalDataLength = (short) (1 + inLength + padLength);
        offset = TLVWriter.writeLength(outBuffer, offset, totalDataLength);

        // V (DATA)

        // Padding byte first
        outBuffer[offset++] = PADDING_INDICATOR;

        // Writing the actual data is handled in the next state routine below, for now we just 
        // update the CMAC with our data TLV header         
        short bytesWritten = (short) (offset - outOffset);
        cspCMAC.update(outBuffer, outOffset, bytesWritten);

        // Track the remaining bytes in our buffer
        bytesRemaining -= bytesWritten;

        // We are now in the OUTGOING_DATA state.
        counters[COUNTER_REMAINING_BYTES_WRAPPED] += inLength + padLength;
        context[OFFSET_STATE] = STATE_OUTGOING_DATA;
      } else {
        // We skip straight to the OUTGOING_STATUS state
        context[OFFSET_STATE] = STATE_OUTGOING_TRAILER;
      }
    }

    //
    // STATE_OUTGOING_DATA --> STATE_OUTGOING_DATA (Partial data write)
    // STATE_OUTGOING_DATA --> STATE_OUTGOING_STATUS (Data completed)
    //
    if (context[OFFSET_STATE] == STATE_OUTGOING_DATA) {

      // Recalculate the padding bytes (since we only encrypt in block-multiples, it will be the same)      
      short cipherLength = (short) (inLength + LENGTH_BLOCK - (inLength % LENGTH_BLOCK));

      // The actual ciphertext bytes emitted. update() MAY emit fewer than we feed in, because a
      // padded cipher can hold back a complete block until doFinal adds the padding.
      short enciphered;

      // Can we fit all remaining ciphertext, including padding bytes in outBuffer?
      if (cipherLength <= bytesRemaining) {

        // Call doFinal, presuming that it will write exactly [cipherLength] bytes
        enciphered = cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, offset);
        if (cipherLength != enciphered) {
          // Insane condition, we're doing something wrong.
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Track the total data bytes we have wrapped
        counters[COUNTER_LAST_BYTES_WRAPPED] = inLength;

        // We are ready to write our TRAILER bytes now
        context[OFFSET_STATE] = STATE_OUTGOING_TRAILER;
      } else {
        // Calculate the largest block-size amount of input data that we can write and encipher it.

        // NOTES:
        // - update() MAY emit fewer bytes than we feed in; the held-back block flushes on a later call
        // - It is possible, however unlikely, that we will write all of the remaining bytes here.
        //   This does not mean we are finished, it just means another call to wrap() will write
        //   just the padding bytes in a doFinal, passing a zero-length data input.
        cipherLength = (short) ((bytesRemaining / LENGTH_BLOCK) * LENGTH_BLOCK);

        // Call update; use the count it actually emitted, which may be fewer than [cipherLength]
        enciphered = cspAES.update(inBuffer, inOffset, cipherLength, outBuffer, offset);

        // Do NOT update the state here, we remain in the OUTGOING_DATA state
        // Track the total data bytes we have wrapped so far
        counters[COUNTER_LAST_BYTES_WRAPPED] = cipherLength;
      }

      // In all cases, update the CMAC with the ciphertext we just calculated 
      cspCMAC.update(outBuffer, offset, enciphered);

      // Update our tracking bytes
      counters[COUNTER_REMAINING_BYTES_WRAPPED] -= enciphered;
      bytesRemaining -= enciphered;
      offset += enciphered;
    }

    //
    // STATE_OUTGOING_TRAILER --> STATE_OUTGOING_TRAILER (Not enough data to write)
    // STATE_OUTGOING_TRAILER --> STATE_OUTGOING_COMPLETE (Wrapping completed)
    // NOTE: We only process this if we have enough remaining space to put the entire trailer TLV    
    //
    if (context[OFFSET_STATE] == STATE_OUTGOING_TRAILER && bytesRemaining >= LENGTH_TRAILER_ENCODED) {

      //
      // Write the STATUS 
      //       
      short statusOffset = offset; // For CMAC calculation
      outBuffer[offset++] = TAG_STATUS;
      outBuffer[offset++] = LENGTH_STATUS;
      offset = Util.setShort(outBuffer, offset, status);

      //
      // MAC
      // 
      outBuffer[offset++] = TAG_MAC;
      outBuffer[offset++] = LENGTH_MAC;

      // Always 
      cspCMAC.sign(outBuffer, statusOffset, LENGTH_STATUS_ENCODED, context, OFFSET_RSP_MCV);
      offset = Util.arrayCopyNonAtomic(context, OFFSET_RSP_MCV, outBuffer, offset, LENGTH_MAC);

      // Update our tracking and progress to the OUTGOING_COMPLETE state
      counters[COUNTER_REMAINING_BYTES_WRAPPED] = 0;
      context[OFFSET_STATE] = STATE_OUTGOING_COMPLETE;
    }

    // Whatever state, we now return the number of ACTUAL bytes we wrote for the caller
    return (short) (offset - outOffset);
  }

  /***
   * Returns the number of INPUT bytes that were processed in the previous call to wrap()
   * @return
   */
  short getLastBytesWrapped() {
    return counters[COUNTER_LAST_BYTES_WRAPPED];
  }

  /***
   * Returns the number of INPUT bytes that were processed in the previous call to wrap()
   * @return
   */
  short getRemainingBytesWrapped() {
    return counters[COUNTER_REMAINING_BYTES_WRAPPED];
  }

  /***
   * Calculates the expected response length for a key establishment operation, given a key.
   * @param key
   * @return
   */
  short getEstablishResponseLength(PIVKeySM key) {
    if (!isInitialised()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    return (short) (cipherSuite.LENGTH_RESPONSE + key.getCvcLength());
  }

  private final class CipherSuite {

    final short LENGTH_REQUEST;
    final short LENGTH_RESPONSE; // Does not include variable CVC length
    final short LENGTH_AES_KEY_BITS;
    final short LENGTH_AES_KEY_BYTES;
    final byte LENGTH_NICC;
    final byte HASH_ALGORITHM;
    final short LENGTH_DKM;
    final byte MECHANISM_ID;

    // Session Keys
    AESKey skCFRM;
    AESKey skMAC;
    AESKey skENC;
    AESKey skRMAC;

    CipherSuite(byte mechanism) {
      if (mechanism == Constants.ID_ALG_ECC_CS2) {
        LENGTH_REQUEST = 74;
        LENGTH_RESPONSE = (short) 33;
        LENGTH_AES_KEY_BITS = (short) 128;
        LENGTH_AES_KEY_BYTES = (short) 16;
        LENGTH_NICC = (short) 16;
        HASH_ALGORITHM = MessageDigest.ALG_SHA_256;
        LENGTH_DKM = (short) 64; // 4 * 16-bytes
      } else {
        LENGTH_REQUEST = 106;
        LENGTH_RESPONSE = (short) 41;
        LENGTH_AES_KEY_BITS = (short) 256;
        LENGTH_AES_KEY_BYTES = (short) 32;
        LENGTH_NICC = (short) 24;
        HASH_ALGORITHM = MessageDigest.ALG_SHA_384;
        LENGTH_DKM = (short) 128; // 4 * 32-bytes
      }
      MECHANISM_ID = mechanism;

      // Generate session keys and CSPs
      skCFRM = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, LENGTH_AES_KEY_BITS, false);
      skMAC = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, LENGTH_AES_KEY_BITS, false);
      skENC = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, LENGTH_AES_KEY_BITS, false);
      skRMAC = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, LENGTH_AES_KEY_BITS, false);
    }

    void clear() {
      skCFRM.clearKey();
      skMAC.clearKey();
      skENC.clearKey();
      skRMAC.clearKey();
    }
  }
}
