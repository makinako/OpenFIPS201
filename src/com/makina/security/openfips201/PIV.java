/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.PIN;
import javacard.framework.Util;

/**
 * Implements FIPS201-2 according to NIST SP800-73-4.
 *
 * <p>It implements the following functionality: - Compiles to Javacard 2.2.2 for maximum
 * compatibility - A flexible filesystem that can be defined easily without recompilation - A
 * flexible key store that defines key roles instead of hard-coding which key is used for what
 * function - Secure personalisation over SCP w/CEnc+CMac using the CHANGE REFERENCE DATA and PUT
 * DATA commands
 *
 * <p>The following is out-of-scope in this revision: - Elliptic curve cryptography mechanisms -
 * Virtual contact interface - Secure messaging using Opacity - Biometric on-card comparison (OCC)
 */
final class PIV {

  //
  // The most important constant of all
  //
  private static final byte ZERO = (byte) 0;

  //
  // Persistent Objects
  //

  // Transient buffer allocation
  static final short LENGTH_SCRATCH = (short) 284;

  //
  // Static PIV identifiers 
  //

  // Data Objects
  static final byte ID_DATA_DISCOVERY = (byte) 0x7E;

  // Keys
  static final byte ID_ALG_DEFAULT = (byte) 0x00; // This maps to TDEA_3KEY
  static final byte ID_ALG_TDEA_3KEY = (byte) 0x03;
  static final byte ID_ALG_RSA_1024 = (byte) 0x06;
  static final byte ID_ALG_RSA_2048 = (byte) 0x07;
  static final byte ID_ALG_AES_128 = (byte) 0x08;
  static final byte ID_ALG_AES_192 = (byte) 0x0A;
  static final byte ID_ALG_AES_256 = (byte) 0x0C;
  static final byte ID_ALG_ECC_P256 = (byte) 0x11;
  static final byte ID_ALG_ECC_P384 = (byte) 0x14;
  static final byte ID_ALG_ECC_CS2 = (byte) 0x27; // Secure Messaging - ECCP256+SHA256
  static final byte ID_ALG_ECC_CS7 = (byte) 0x2E; // Secure Messaging - ECCP384+SHA384

  // Cardholder Verification Methods
  static final byte ID_CVM_GLOBAL_PIN = (byte) 0x00;
  static final byte ID_CVM_LOCAL_PIN = (byte) 0x80;
  static final byte ID_CVM_PUK = (byte) 0x81;
  static final byte ID_CVM_OCC_PRI = (byte) 0x96;
  static final byte ID_CVM_OCC_SEC = (byte) 0x97;
  static final byte ID_CVM_PAIRING_CODE = (byte) 0x98;

  // General Authenticate Tags
  static final byte CONST_TAG_AUTH_TEMPLATE = (byte) 0x7C;
  static final byte CONST_TAG_AUTH_WITNESS = (byte) 0x80;
  static final byte CONST_TAG_AUTH_CHALLENGE = (byte) 0x81;
  static final byte CONST_TAG_AUTH_CHALLENGE_RESPONSE = (byte) 0x82;
  static final byte CONST_TAG_AUTH_EXPONENTIATION = (byte) 0x85;

  //
  // PIV-specific ISO 7816 STATUS WORD (SW12) responses
  //
  static final short SW_RETRIES_REMAINING = (short) 0x63C0;

  /*
   * PIV APPLICATION CONSTANTS
   */
  static final short SW_REFERENCE_NOT_FOUND = (short) 0x6A88;
  static final short SW_OPERATION_BLOCKED = (short) 0x6983;

  static final short SW_PUT_DATA_COMMAND_MISSING = (short) 0x6E10;
  static final short SW_PUT_DATA_COMMAND_INVALID_LENGTH = (short) 0x6E11;
  static final short SW_PUT_DATA_OP_MISSING = (short) 0x6E12;
  static final short SW_PUT_DATA_OP_INVALID_LENGTH = (short) 0x6E13;
  static final short SW_PUT_DATA_OP_INVALID_VALUE = (short) 0x6E14;
  static final short SW_PUT_DATA_ID_MISSING = (short) 0x6E15;
  static final short SW_PUT_DATA_ID_INVALID_LENGTH = (short) 0x6E16;
  static final short SW_PUT_DATA_MODE_CONTACT_MISSING = (short) 0x6E17;
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH = (short) 0x6E18;
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_VALUE = (short) 0x6E19;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_MISSING = (short) 0x6E1A;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH = (short) 0x6E1B;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_VALUE = (short) 0x6E1C;
  static final short SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH = (short) 0x6E1D;
  static final short SW_PUT_DATA_KEY_MECHANISM_MISSING = (short) 0x6E1E;
  static final short SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH = (short) 0x6E1F;
  static final short SW_PUT_DATA_KEY_ROLE_MISSING = (short) 0x6E20;
  static final short SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH = (short) 0x6E21;
  static final short SW_PUT_DATA_KEY_ATTR_MISSING = (short) 0x6E22;
  static final short SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH = (short) 0x6E23;
  static final short SW_PUT_DATA_CONFIG_MISSING = (short) 0x6E24;
  static final short SW_PUT_DATA_CONFIG_WRONG_LENGTH = (short) 0x6E25;
  static final short SW_PUT_DATA_CONFIG_INVALID_VALUE = (short) 0x6E26;
  static final short SW_PUT_DATA_OBJECT_EXISTS = (short) 0x6E27;

  // The current authentication stage
  private static final short OFFSET_AUTH_STATE = ZERO;

  // The key id used in the current authentication
  private static final short OFFSET_AUTH_ID = (short) 1;

  // The key mechanism used in the current authentication
  private static final short OFFSET_AUTH_MECHANISM = (short) 2;

  // The GENERAL AUTHENTICATE challenge buffer
  private static final short OFFSET_AUTH_CHALLENGE = (short) 3;

  //
  // Cryptographic Mechanism Identifiers
  // SP800-73-4 Part 1: 5.3 - Table 5 and
  // SP800-78-4 5.3 - Table 6-2
  //
  // The length to allocate for holding CHALLENGE or WITNESS data for general authenticate
  // NOTE: Since RSA is only involved in INTERNAL AUTHENTICATE, we only need to cater for
  //		 up to an AES block size
  private static final short LENGTH_CHALLENGE = (short) 16;
  private static final short LENGTH_AUTH_STATE = (short) (5 + LENGTH_CHALLENGE);

  // GENERAL AUTHENTICATE is in its initial state
  // A CHALLENGE has been requested by the client application (Basic Authentication)
  private static final short AUTH_STATE_EXTERNAL = (short) 1;
  // A WITNESS has been requested by the client application (Mutual Authentication)
  private static final short AUTH_STATE_MUTUAL = (short) 2;

  // PERSISTENT - Command Chaining Handler
  private final ChainBuffer chainBuffer;
  // PERSISTENT - Cryptography Service Provider
  private final PIVSecurityProvider cspPIV;
  // PERSISTENT - Configuration Store
  private final Config config;
  // PERSISTENT - Data Store
  private PIVDataObject firstDataObject;

  // TRANSIENT - A working area to hold intermediate data and outgoing buffers
  private final byte[] scratch;
  // TRANSIENT - Holds any authentication related intermediary state
  private final byte[] authenticationContext;

  /** Constructor */
  PIV() {

    //
    // Data Allocation
    //

    // Create our transient buffers
    scratch = JCSystem.makeTransientByteArray(LENGTH_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
    authenticationContext =
        JCSystem.makeTransientByteArray(LENGTH_AUTH_STATE, JCSystem.CLEAR_ON_DESELECT);

    // Create our configuration provider
    config = new Config();

    // Create our chainBuffer reference and make sure its state is cleared
    chainBuffer = new ChainBuffer();

    // Create our PIV Security Provider
    cspPIV =
        new PIVSecurityProvider(
            config.readValue(Config.CONFIG_PIN_RETRIES_CONTACT),
            config.readValue(Config.CONFIG_PUK_RETRIES_CONTACT));

    // Create our TLV objects (we don't care about the result, this is just to allocate)
    TLVReader.getInstance();
    TLVWriter.getInstance();

    // NOTE:
    // - Javacard does not specify the behaviour of an OwnerPIN that has not ever been
    //   initialised with a value, so we explicitly set one to prevent usage.
    //

    // Generate a random PIN value to initialise it
    PIVCrypto.doGenerateRandom(scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH);
    cspPIV.updatePIN(ID_CVM_LOCAL_PIN, scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH, ZERO);
    PIVSecurityProvider.zeroise(scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH);

    // Generate a random PUK value to initialise it
    PIVCrypto.doGenerateRandom(scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH);
    cspPIV.updatePIN(ID_CVM_PUK, scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH, ZERO);
    PIVSecurityProvider.zeroise(scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH);

    //
    // NOTE: We do not initialise the Global PIN as this may have been managed externally.
    //
  }

  /**
   * Starts or continues processing of an incoming data stream, which will be written directly to a
   * buffer
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset to read from
   * @param length The length of the data to read
   */
  void processIncomingObject(byte[] buffer, short offset, short length) {
    chainBuffer.processIncomingObject(buffer, offset, length);
  }

  /**
   * Starts or continues processing for an outgoing buffer being transmitted to the host
   *
   * @param apdu The current APDU buffer to transmit with
   */
  void processOutgoing(APDU apdu) {
    chainBuffer.processOutgoing(apdu);
  }

  /**
   * Called when this applet is selected, returning the APT object
   *
   * @param buffer The APDU buffer to write the APT to
   * @param offset The starting offset of the CDATA section
   * @return The length of the returned APT object
   */
  short select(byte[] buffer, short offset) {

    //
    // PRE-CONDITIONS
    //

    // NONE

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Return the APT
    Util.arrayCopyNonAtomic(
        Config.TEMPLATE_APT, ZERO, buffer, offset, (short) Config.TEMPLATE_APT.length);

    return (short) Config.TEMPLATE_APT.length;
  }

  /**
   * Handles the PIV requirements for deselection of the application. Although this is not
   * explicitly stated as a PIV card command, its functionality is implied in the SELECT
   */
  void deselect() {

    // If the currently selected application is the PIV Card Application when the SELECT command is
    // given and the AID in the data field of the SELECT command is either the AID of the PIV Card
    // Application or the right-truncated version thereof, then the PIV Card Application shall
    // continue to be the currently selected card application and the setting of all security status
    // indicators in the PIV Card Application shall be unchanged.

    // If the currently selected application is the PIV Card Application when the SELECT command is
    // given and the AID in the data field of the SELECT command is not the PIV Card Application (or
    // the right truncated version thereof), but a valid AID supported by the ICC, then the PIV Card
    // Application shall be deselected and all the PIV Card Application security status indicators
    // in the PIV Card Application shall be set to FALSE.

    // Reset all security conditions in the security provider
    cspPIV.clearAuthenticatedKey();
    cspPIV.clearVerification();
  }

  private short buildDiscoveryObject(byte[] buffer, short offset) {

    short length = (short) Config.TEMPLATE_DISCOVERY.length;

    // Write the template
    offset = Util.arrayCopyNonAtomic(Config.TEMPLATE_DISCOVERY, ZERO, buffer, offset, length);

    // Move the offset back by 2 so we can write our policy bytes
    offset -= (byte) 2;

    // Tag 0x5F2F encodes the PIN Usage Policy in two bytes:
    // FIRST BYTE
    // -----------------------------
    buffer[offset++] =
        (byte)
            // Bit 8 of the first byte shall be set to zero

            // Bit 7 is set to 1 to indicate that the mandatory PIV Card Application PIN
            // satisfies the PIV Access Control Rules (ACRs) for command
            // execution and data object access.
            ((config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL) ? (byte) (1 << 6) : (byte) 0)

                // Bit 6 indicates whether the optional Global PIN satisfies the PIV ACRs for
                // command execution and PIV data object access.
                | (config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL) ? (byte) (1 << 5) : (byte) 0)

            // Bit 5 indicates whether the optional OCC satisfies the PIV ACRs for
            // command execution and PIV data object access
            // | (config.readFlag(Config.CONFIG_OCC_MODE) ? (byte) (1 << 4) : (byte) 0)

            // Bit 4 indicates whether the optional VCI is implemented
            // | (config.readFlag(Config.CONFIG_VCI_MODE) ? (byte) (1 << 3) : (byte) 0)

            // Bit 3 is set to zero if the pairing code is required to establish a VCI and is
            // set to one if a VCI is established without pairing code
            // | (byte) (0 << 2)

            // Bits 2 and 1 of the first byte shall be set to zero
            );

    // SECOND BYTE
    // -----------------------------
    // The second byte of the PIN Usage Policy encodes the cardholder's PIN preference for
    // PIV Cards with both the PIV Card Application PIN and the Global PIN enabled:

    // 0x10 indicates that the PIV Card Application PIN is the primary PIN used
    // 	 	to satisfy the PIV ACRs for command execution and object access.
    // 0x20 indicates that the Global PIN is the primary PIN used to satisfy the
    // 		PIV ACRs for command execution and object access.
    buffer[offset] = (config.readFlag(Config.CONFIG_PIN_PREFER_GLOBAL) ? (byte) 0x20 : (byte) 0x10);

    return length;
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @return The length of the entire data object
   */
  short getData(byte[] buffer, short offset) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;

    final byte CONST_TAG_DISCOVERY = (byte) 0x7E;
    final byte CONST_TAG_BIOMETRIC_1 = (byte) 0x7F;
    final byte CONST_TAG_BIOMETRIC_2 = (byte) 0x61;
    final byte CONST_TAG_NORMAL_1 = (byte) 0x5F;
    final byte CONST_TAG_NORMAL_2 = (byte) 0xC1;

    final short CONST_LEN_DISCOVERY = (short) 0x01;
    final short CONST_LEN_BIOMETRIC = (short) 0x02;
    final short CONST_LEN_NORMAL = (short) 0x03;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'TAG' data element must be present
    // NOTE: This is parsed manually rather than going through a TLV parser
    if (buffer[offset++] != CONST_TAG) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Check SW12
    }

    //
    // Retrieve the data object TAG identifier
    // NOTE: All objects in the datastore have had their tag reduced to one byte, which is
    //		 always the least significant byte of the tag.
    //

    byte id = 0;

    switch (buffer[offset]) {

        //
        // SPECIAL CASE 1 - DISCOVERY OBJECT
        //
      case CONST_LEN_DISCOVERY:
        offset++; // Move to the 1st byte of the tag
        if (buffer[offset] != CONST_TAG_DISCOVERY) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        id = CONST_TAG_DISCOVERY; // Store it as our object ID
        break;

        //
        // SPECIAL CASE 2 - BIOMETRIC INFORMATION TEMPLATE
        //
      case CONST_LEN_BIOMETRIC:
        offset++; // Move to the 1st byte of the tag
        if (buffer[offset] != CONST_TAG_BIOMETRIC_1)
          ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        offset++; // Move to the 2nd byte
        if (buffer[offset] != CONST_TAG_BIOMETRIC_2)
          ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        id = CONST_TAG_BIOMETRIC_2; // Store it as our object ID
        break;

        //
        // ALL OTHER OBJECTS
        //
      case CONST_LEN_NORMAL:
        offset++; // Move to the 1st byte of the tag
        if (buffer[offset] != CONST_TAG_NORMAL_1) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        offset++; // Move to the 2nd byte
        if (buffer[offset] != CONST_TAG_NORMAL_2) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

        offset++; // Move to the 3rd byte
        id = buffer[offset]; // Store it as our object ID
        break;

      default:
        // Unsupported length supplied
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    PIVDataObject object = findDataObject(id);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return ZERO; // Keep static analyser happy
    }

    // PRE-CONDITION 2 - The access rules must be satisfied for the requested object
    if (!cspPIV.checkAccessModeObject(object)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The requested object must be initialised with data
    // NOTE: The special discovery object is not included in this check as it is generated
    // for each call.
    if (id != ID_DATA_DISCOVERY && !object.isInitialised()) {

      // 4.1.1 Data Object Content
      // Before the card is issued, data objects that are created but not used shall be set to
      // zero-length value.
      //
      // NOTE:
      // This description doesn't explicitly say whether the entire response should be zero
      // (i.e. SW12 only), or to return the data object tag with a zero length.
      //
      // TODO: Review what the NIST test cards do in this instance! That should be the default
      if (config.readFlag(Config.OPTION_READ_EMPTY_DATA_OBJECT)) {
        // We just return an OK response with no data
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
      } else {
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      }
      return ZERO; // Keep static analyser happy
    }

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Handle the dynamic discovery object case
    //
    short length;
    byte[] data;
    if (id == ID_DATA_DISCOVERY) {
      length = buildDiscoveryObject(scratch, ZERO);
      data = scratch;
    } else {
      length = object.getLength();
      data = object.content;
    }

    // STEP 2 - Set up the outgoing chainbuffer
    chainBuffer.setOutgoing(data, ZERO, length, false);

    // Done - return how many bytes we will process
    return length;
  }

  /**
   * The PUT DATA card command completely replaces the data content of a single data object in the
   * PIV Card Application with new content.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   */
  void putData(byte[] buffer, short offset, short length) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final byte CONST_DATA = (byte) 0x53;

    final byte CONST_TAG_DISCOVERY = (byte) 0x7E;
    final byte CONST_TAG_BIOMETRIC_1 = (byte) 0x7F;
    final byte CONST_TAG_BIOMETRIC_2 = (byte) 0x61;
    final byte CONST_TAG_NORMAL_1 = (byte) 0x5F;
    final byte CONST_TAG_NORMAL_2 = (byte) 0xC1;

    final short CONST_LEN_NORMAL = (short) 0x03;

    //
    // PRE-CONDITIONS
    //

    // Store the supplied data offset so we can use it to calculate the length of the object later
    short initialOffset = offset;

    // PRE-CONDITION 1 - The tag must be one of the correctly formatted tag identifiers
    // NOTE: We don't support the OpenFIPS201 extended tag 2F here.

    //
    // Retrieve the data object TAG identifier
    // NOTE: All objects in the datastore have had their tag reduced to one byte, which is
    //		 always the least significant byte of the tag.
    //
    byte id = 0;

    switch (buffer[offset]) {

        //
        // SPECIAL OBJECT - Discovery Object
        //
      case CONST_TAG_DISCOVERY:
        id = CONST_TAG_DISCOVERY;
        break;

        //
        // SPECIAL OBJECT - Biometric Information Template Group
        //
      case CONST_TAG_BIOMETRIC_1:
        if (buffer[(short) (offset + 1)] != CONST_TAG_BIOMETRIC_2) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        id = CONST_TAG_BIOMETRIC_2; // Store it as our object ID
        break;

        //
        // All other objects
        //
      case CONST_TAG:
        offset++; // Move to the length byte
        if (buffer[offset] != CONST_LEN_NORMAL) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        offset++; // Move to the first tag data byte
        if (buffer[offset] != CONST_TAG_NORMAL_1) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

        offset++; // Move to the second tag data byte
        if (buffer[offset] != CONST_TAG_NORMAL_2) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

        offset++; // Move to the third tag data byte (which is our identifier)
        id = buffer[offset]; // Store it as our object ID

        // PRE-CONDITION 2 - For other objects, the 'DATA' tag must be present in the buffer
        offset++; // Move to the DATA tag
        if (buffer[offset] != CONST_DATA) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return; // Keep static analyser happy
        }
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
    }

    // The offset now holds the correct position for writing the object, including the DATA tag

    // PRE-CONDITION 3 - The tag supplied in the 'TAG LIST' element must exist in the data store
    PIVDataObject object = findDataObject(id);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 4 - The access rules must be satisfied for write access, either with an
    // administrative role or if the data object has explicit permission to write.
    if (!cspPIV.checkAccessModeAdmin(object)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Decide whether to clear or write/update
    short objectLength = TLVReader.getLength(buffer, offset);

    // If the data object length is zero, the caller is requesting that the object be cleared.
    if (objectLength == 0) {
      // STEP 2a - Clear the object
      object.clear();
    } else {
      // STEP 2b - Calculate the total length of the object to allocate including TLV tag+length
      objectLength += (short) (TLVReader.getDataOffset(buffer, offset) - offset);

      // STEP 3 - Allocate the data object
      // NOTE: if the passed length is zero, this method will
      object.allocate(objectLength);

      // STEP 4 - Recalculate the length of the first write, to account for the tag element being
      // removed
      length -= (short) (offset - initialOffset);

      // STEP 5 - Set up the incoming chainbuffer
      chainBuffer.setIncomingObject(object.content, ZERO, objectLength, false);

      // STEP 6 - Start processing the first segment of data here so we can give it our modified
      // offset / length
      chainBuffer.processIncomingObject(buffer, offset, length);
    }
  }

  /**
   * The VERIFY card command initiates the comparison in the card of the reference data indicated by
   * the key reference with authentication data in the data field of the command.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void verify(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    switch (id) {
      case ID_CVM_GLOBAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_GLOBAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      case ID_CVM_LOCAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_LOCAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // PRE-CONDITION 2 - The PIN must be permitted to operate over the current interface
    if (cspPIV.getIsContactless()
        && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
        && !config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The supplied PIN format must be valid
    // If the key reference is '00' or '80' and the authentication data in the command data
    // field does not satisfy the criteria in Section 2.4.3, then the card command shall fail
    // and the PIV Card Application shall return either the status word '6A 80' or '63 CX'.
    // If status word '6A 80' is returned, the security status and the retry counter of the key
    // reference shall remain unchanged. If status word '63 CX' is returned, the security
    // status of the key reference shall be set to FALSE and the retry counter associated with
    // the key reference shall be decremented by one.
    // NOTE: We return 6A80 (WRONG DATA) and therefore do NOT decrement the counter or block
    if (!verifyPinFormat(buffer, offset, length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The PIN must not be blocked
    if (pin.getTriesRemaining() == (byte) 0) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // PRE-CONDITION 5 - If using the contactless interface, the pin retries remaining must not
    //					 fall below the specified intermediate retry amount

    // In order to protect against blocking over the contactless interface, PIV Card Applications
    // that implement secure messaging shall define an issuer-specified intermediate retry value for
    // each of these key references and return '69 83' if the command is submitted over the
    // contactless interface (over secure messaging or the VCI, as required for the key reference)
    // and the current value of the retry counter associated with the key reference is at or below
    // the issuer-specified intermediate retry value. If status word '69 83' is returned, then the
    // comparison shall not be made, and the security status and the retry counter of the key
    // reference shall remain unchanged.
    if (cspPIV.getIsContactless() && (pin.getTriesRemaining() <= config.getIntermediatePIN())) {
      ISOException.throwIt(SW_OPERATION_BLOCKED);
    }

    //
    // EXECUTION STEPS
    //

    // Verify the PIN
    if (!pin.check(buffer, offset, (byte) length)) {

      // Check for blocked again
      if (pin.getTriesRemaining() == (byte) 0) ISOException.throwIt(SW_OPERATION_BLOCKED);

      // Return the number of retries remaining
      ISOException.throwIt((short) (SW_RETRIES_REMAINING | (short) pin.getTriesRemaining()));
    }

    // Verified, set the PIN ALWAYS flag
    cspPIV.setPINAlways(true);
  }

  /**
   * Implements the variant of the 'VERIFY' command that returns the status of the requested PIN
   *
   * @param id The requested PIN reference
   */
  void verifyGetStatus(byte id) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    // PRE-CONDITION 2 - We must be permitted to operate over the current interface
    if (cspPIV.getIsContactless()
        && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
        && !config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    switch (id) {
      case ID_CVM_GLOBAL_PIN:

        // Make sure CONFIG_PIN_ENABLE_GLOBAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      case ID_CVM_LOCAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_LOCAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // If P1='00', and Lc and the command data field are absent, the command can be used to retrieve
    // the number of further retries allowed ('63 CX'), or to check whether verification is not
    // needed ('90 00').

    // Check for a blocked PIN
    if (pin.getTriesRemaining() == (byte) 0) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // If we are not validated
    if (!pin.isValidated()) {
      // Return the number of retries remaining
      ISOException.throwIt((short) (SW_RETRIES_REMAINING | (short) pin.getTriesRemaining()));
    }

    // If we got this far we are authenticated, so just return (9000)
  }

  /**
   * Implements the variant of the 'VERIFY' command that resets the authentication state of the
   * requested PIN
   *
   * @param id The requested PIN reference
   */
  void verifyResetStatus(byte id) throws ISOException {

    // The security status of the key reference specified in P2 shall be set to FALSE and
    // the retry counter associated with the key reference shall remain unchanged.

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    // PRE-CONDITION 2 - We must be permitted to operate over the current interface
    if (cspPIV.getIsContactless()
        && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
        && !config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    switch (id) {
      case ID_CVM_GLOBAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_GLOBAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      case ID_CVM_LOCAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_LOCAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // Reset the requested PIN
    pin.reset();

    // Reset the PIN ALWAYS flag
    cspPIV.setPINAlways(false);
  }

  /**
   * The CHANGE REFERENCE DATA card command initiates the comparison of the authentication data in
   * the command data field with the current value of the reference data and, if this comparison is
   * successful, replaces the reference data with new reference data.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void changeReferenceData(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    // PRE-CONDITION 2
    // Only reference data associated with key references '80' and '81' specific to the PIV Card
    // Application (i.e., local key reference) and the Global PIN with key reference '00' may be
    // changed by the PIV Card Application CHANGE REFERENCE DATA command.
    // Key reference '80' reference data shall be changed by the PIV Card Application CHANGE
    // REFERENCE DATA command. The ability to change reference data associated with key references
    // '81' and '00' using the PIV Card Application CHANGE REFERENCE DATA command is optional.

    // If key reference '81' is specified and the command is submitted over the contactless
    // interface (including SM or VCI), then the card command shall fail. If key reference
    // '00' or '80' is specified and the command is not submitted over either the contact interface
    // or the VCI, then the card command shall fail. In each case, the security status and the
    // retry counter
    // of the key reference shall remain unchanged.

    // NOTE: This is handled in the switch statement and is configurable at compile-time
    byte intermediateRetries;
    boolean puk = false;

    switch (id) {
      case ID_CVM_GLOBAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_GLOBAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }

        // Check whether we are allowed to operate over contactless if applicable
        if (cspPIV.getIsContactless()
            && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
            && !config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // NOTE: This will only work if the 'CVM Management' applet privilege has been set
        intermediateRetries = config.getIntermediatePIN();
        break;

      case ID_CVM_LOCAL_PIN:
        // Make sure CONFIG_PIN_ENABLE_LOCAL is set
        if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }

        // Check whether we are allowed to operate over contactless if applicable
        if (cspPIV.getIsContactless()
            && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
            && !config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        intermediateRetries = config.getIntermediatePIN();

        break;

      case ID_CVM_PUK:
        // Make sure CONFIG_PUK_ENABLED is set
        if (!config.readFlag(Config.CONFIG_PUK_ENABLED)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }

        // Check whether we are allowed to operate over contactless if applicable
        if (cspPIV.getIsContactless()
            && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
            && !config.readFlag(Config.CONFIG_PUK_PERMIT_CONTACTLESS)) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        intermediateRetries = config.getIntermediatePUK();
        puk = true;
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // If the current value of the retry counter associated with the key reference is zero, then the
    // reference data associated with the key reference shall not be changed and the
    // PIV Card Application shall return the status word '69 83'.
    if (pin.getTriesRemaining() == ZERO) {
      ISOException.throwIt(SW_OPERATION_BLOCKED);
    }

    // If the command is submitted over the contactless interface (VCI) and the current value of the
    // retry counter associated with the key reference is at or below the issuer-specified
    // intermediate retry value (see Section 3.2.1),
    // then the reference data associated with the key reference shall not be changed and the PIV
    // Card Application shall return the status word '69 83'.
    if (cspPIV.getIsContactless() && (pin.getTriesRemaining()) <= intermediateRetries) {
      ISOException.throwIt(SW_OPERATION_BLOCKED);
    }

    // If the authentication data in the command data field does not match the current value of the
    // reference data or if either the authentication data or the new reference data in the command
    // data field of the command does not satisfy the criteria in Section 2.4.3, the PIV Card
    // Application shall not change the reference data
    // associated with the key reference and shall return either status word '6A 80' or '63 CX',
    // with the following restrictions.
    // SIMPLIFIED: If [Old PIN format is BAD] or [New PIN format is BAD] you can choose 6A80 or
    // 63CX. We choose 6A80

    // If the authentication data in the command data field satisfies the criteria in Section 2.4.3
    // and matches the current value of the reference data, but the new reference data in the
    // command data field of the command does not satisfy the criteria in Section 2.4.3, the PIV
    // Card Application shall return status word '6A 80'.
    // SIMPLIFIED: If [Old PIN is GOOD] but [New PIN format is BAD], use 6A80.

    // If the authentication data in the command data field does not match the current value of the
    // reference data, but both the authentication data and the new reference data in the command
    // data field of the command satisfy the criteria in Section 2.4.3, the PIV Card Application
    // shall return status word '63 CX'.
    // SIMPLIFIED: If [Old PIN format is GOOD] but [Old PIN is BAD], use 63CX and decrement.

    // If status word '6A 80' is returned, the security status and retry counter associated with the
    // key reference shall remain unchanged.9 If status word '63 CX' is returned, the security
    // status of the key reference shall be set to FALSE and the retry counter associated with the
    // key reference shall be decremented by one.

    // If the new reference data (PIN) in the command data field of the command does not satisfy the
    // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A
    // 80'.

    // Ensure the supplied length is exactly two maximum lengths
    byte pinLength;
    if (puk) {
      pinLength = config.readValue(Config.CONFIG_PUK_LENGTH);
    } else {
      pinLength = config.readValue(Config.CONFIG_PIN_MAX_LENGTH);
    }
    if (length != (short) (pinLength + pinLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Verify the authentication reference data (old PIN/PUK) format
    if (!puk) {
      if (!verifyPinFormat(buffer, offset, pinLength)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    // Verify the authentication reference data (old PIN/PUK) value
    if (!pin.check(buffer, offset, pinLength)) {
      // Return the number of retries remaining
      ISOException.throwIt((short) (SW_RETRIES_REMAINING | (short) pin.getTriesRemaining()));
    }

    // Move to the new reference data
    offset += pinLength;

    // Verify the new reference data (new PIN/PUK)
    if (!puk) {
      if (!verifyPinFormat(buffer, offset, pinLength)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      // Since this is the new value, apply our PIN complexity rules
      if (!verifyPinRules(buffer, offset, pinLength)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the security status of the key reference shall be set to
    // TRUE and the retry counter associated with the key reference shall be set to the reset retry
    // value associated with the key reference.

    // STEP 1 - Update the PIN
    cspPIV.updatePIN(id, buffer, offset, pinLength, config.readValue(Config.CONFIG_PIN_HISTORY));

    // STEP 2 - Verify the new PIN, which will have the effect of setting it to TRUE and resetting
    // the retry counter
    pin.check(buffer, offset, pinLength);

    // STEP 3 - Set the PIN ALWAYS flag as this is now verified (if it is not the PUK)
    if (!puk) {
      cspPIV.setPINAlways(true);
    }

    // Done
  }

  /**
   * The RESET RETRY COUNTER card command resets the retry counter of the PIN to its initial value
   * and changes the reference data. The command enables recovery of the PIV Card Application PIN in
   * the case that the cardholder has forgotten the PIV Card Application PIN.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void resetRetryCounter(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The LOCAL PIN must be enabled
    if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION 2 - The PUK must be enabled
    if (!config.readFlag(Config.CONFIG_PUK_ENABLED)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - Check if we are permitted to use this command over the contactless
    // interface.
    // NOTE: We must check this for both the PIN and the PUK
    /*
      Truth table because there's a few balls in the air here:
      IS_CTLESS	IGNORE_ACL	PIN_PERMIT	PUK_PERMIT	RESULT
      ----------------------------------------------------
      FALSE		X			X			X			FALSE
      TRUE		TRUE		X			X			FALSE
      TRUE		FALSE		TRUE		TRUE		FALSE
      TRUE		FALSE		TRUE		FALSE		TRUE
      TRUE		FALSE		FALSE		TRUE		TRUE
      TRUE		FALSE		FALSE		FALSE		TRUE
    */
    if (cspPIV.getIsContactless()
        && !config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)
        && !(config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS)
            && config.readFlag(Config.CONFIG_PUK_PERMIT_CONTACTLESS))) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 4 - The supplied ID must be the Card PIN
    // The only key reference allowed in the P2 parameter of the RESET RETRY COUNTER command is the
    // PIV Card Application PIN. If a key reference is specified in P2 that is not supported by the
    // card, the PIV Card Application shall return the status word '6A 88'.
    if (id != ID_CVM_LOCAL_PIN) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 5 - The supplied length must equal the PUK + NEW PIN lengths
    byte pinLength = config.readValue(Config.CONFIG_PIN_MAX_LENGTH);
    short expectedLength = (short) (config.readValue(Config.CONFIG_PUK_LENGTH) + pinLength);

    if (length != expectedLength) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // PRE-CONDITION 6 - The PUK must not be blocked
    // If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall
    // not be reset and the PIV Card Application shall return the status word '69 83'.
    PIN puk = cspPIV.getPIN(ID_CVM_PUK);
    if (puk == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return; // Keep compiler happy
    }
    if (puk.getTriesRemaining() == ZERO) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // PRE-CONDITION 7 - Verify the PUK value
    // If the reset retry counter authentication data (PUK) in the command data field of the command
    // does not match reference data associated with the PUK, then the PIV Card Application shall
    // return the status word '63 CX'.
    if (!puk.check(buffer, offset, pinLength)) {

      // Reset the PIN's security condition (see paragraph below for explanation)
      pin.reset();

      // Check again if we are blocked
      if (puk.getTriesRemaining() == ZERO) {
        ISOException.throwIt(SW_OPERATION_BLOCKED);
      } else {
        // Return the number of retries remaining
        ISOException.throwIt((short) (SW_RETRIES_REMAINING | (short) puk.getTriesRemaining()));
      }
    }

    // Move to the start of the new PIN
    offset += config.readValue(Config.CONFIG_PUK_LENGTH);

    // PRE-CONDITION 8 - Check the format of the NEW pin value
    // If the new reference data (PIN) in the command data field of the command does not satisfy the
    // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A
    // 80'.
    if (!verifyPinFormat(buffer, offset, pinLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Since this will be the new value, apply our PIN complexity rules
    if (!verifyPinRules(buffer, offset, pinLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // If the reset retry counter authentication data (PUK) in the command data field of the command
    // does not match reference data associated with the PUK and the new reference data (PIN) in the
    // command data field of the command does not satisfy the criteria in Section 2.4.3, then the
    // PIV Card Application shall return either status word '6A 80' or '63 CX'. If the PIV Card
    // Application returns status word '6A 80', then the retry counter associated with the PIN shall
    // not be reset, the security status of the PIN's key reference shall remain unchanged, and the
    // PUK's retry counter shall remain unchanged.11 If the PIV Card Application returns status word
    // '63 CX', then the retry counter associated with the PIN shall not be reset, the security
    // status of the PIN's key reference shall be set to FALSE, and the PUK's retry counter shall
    // be decremented by one.

    // NOTES:
    // - We implicitly decrement the PUK counter if the PUK is incorrect (63CX)
    // - Because we validate the PIN format before checking the PUK, we return WRONG DATA (6A80) in
    // this case
    // - If the PUK check fails, we explicitly reset the PIN's security condition

    // If the card command succeeds, then the PIN's retry counter shall be set to its reset retry
    // value. Optionally, the PUK's retry counter may be set to its initial reset retry value.
    // The security status of the PIN's key reference shall not be changed.

    // NOTE: Since the PUK was verified, the OwnerPIN object automatically resets the PUK counter,
    // which governs the above behaviour

    // Update, reset and unblock the PIN
    cspPIV.updatePIN(id, buffer, offset, pinLength, config.readValue(Config.CONFIG_PIN_HISTORY));
  }

  /**
   * Allows the applet to provide state information to PIV for access control
   *
   * @param value Sets whether the current interface is contactless
   */
  void setIsContactless(boolean value) {

    // This can be overriden by configuration to ignore the contactless interface
    if (config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)) {
      value = false;
    }
    cspPIV.setIsContactless(value);
  }

  boolean isInterfacePermitted() {
    return !config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_GLOBAL);
  }

  /***
   * Indicates whether administration is allowed over the current communications media.
   * Note that this DOES NOT mean there is a valid administrative session!
   * @return True if administrative commands are permitted in the current context.
   */
  boolean isInterfacePermittedForAdmin() {

    // Administration is always permitted over the contact interface
    if (!cspPIV.getIsContactless()) return true;

    // Administration is only allowed over the contactless interface if the
    // OPTION_RESTRICT_CONTACTLESS_ADMIN flag is NOT SET
    return !config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_ADMIN);
  }

  /**
   * Allows the applet to provide security state information to PIV for access control
   *
   * @param value Sets whether the current command was issued over a GlobalPlatform Secure Channel
   */
  void setIsSecureChannel(boolean value) {
    cspPIV.setIsSecureChannel(value);
  }

  /** Clears any intermediate authentication status used by 'GENERAL AUTHENTICATE' */
  private void authenticateReset() throws ISOException {
    PIVSecurityProvider.zeroise(authenticationContext, ZERO, LENGTH_AUTH_STATE);
  }

  /**
   * The GENERAL AUTHENTICATE card command performs a cryptographic operation, such as an
   * authentication protocol, using the data provided in the data field of the command and returns
   * the result of the cryptographic operation in the response data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The offset of the CDATA element
   * @param length The length of the CDATA element
   * @return The length of the return data
   */
  short generalAuthenticate(byte[] buffer, short offset, short length) throws ISOException {

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is more
    // of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return length;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer still contains the APDU header.

    // Set up our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key reference and mechanism must point to an existing key
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[ISO7816.OFFSET_P1]);

    if (key == null) {
      // If any key reference value is specified that is not supported by the card, the PIV Card
      // Application shall return the status word '6A 88'.
      cspPIV.setPINAlways(false); // Clear the PIN ALWAYS flag
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 2 - The access rules must be satisfied for the requested key
    // NOTE: A call to this method automatically clears the PIN ALWAYS status.
    if (!cspPIV.checkAccessModeObject(key)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 3 - The key's private or secret values must have been set
    if (!key.isInitialised()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 4 - The Dynamic Authentication Template tag must be present in the data
    if (!reader.find(CONST_TAG_AUTH_TEMPLATE)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return ZERO; // Keep compiler happy
    }

    // Move into the content of the template
    reader.moveInto();

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Traverse the TLV to determine what combination of elements exist
    //
    short challengeOffset = ZERO;
    short witnessOffset = ZERO;
    short responseOffset = ZERO;
    short exponentiationOffset = ZERO;

    short challengeLength = ZERO;
    short witnessLength = ZERO;
    short responseLength = ZERO;
    short exponentiationLength = ZERO;

    // Save the offset in the TLV object
    offset = reader.getOffset();

    // Loop through all tags
    do {
      if (reader.match(CONST_TAG_AUTH_CHALLENGE)) {
        challengeOffset = reader.getDataOffset();
        challengeLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_CHALLENGE_RESPONSE)) {
        responseOffset = reader.getDataOffset();
        responseLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_WITNESS)) {
        witnessOffset = reader.getDataOffset();
        witnessLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_EXPONENTIATION)) {
        exponentiationOffset = reader.getDataOffset();
        exponentiationLength = reader.getLength();
      } else {
        // We have come across an unknown tag value. Other implementations ignore these and so shall
        // we.
      }
    } while (reader.moveNext());

    // Restore the offset in the TLV object
    reader.setOffset(offset);

    //
    // STEP 2 - Process the appropriate GENERAL AUTHENTICATE case
    //

    //
    // IMPLEMENTATION NOTES
    // --------------------
    // There are 6 authentication cases that make up all of the GENERAL AUTHENTICATE functionality.
    // The first case (Internal Authenticate) has 4 different mode variants depending on the key
    // type
    // and attributes.
    //
    // CASE 1 - INTERNAL AUTHENTICATE
    //
    // Description:
    // The CLIENT presents a CHALLENGE to the CARD, which then returns the encrypted/signed
    // CHALLENGE RESPONSE. This is handled in 3 different mode variants, depending on the keys.
    //	  a. TDEA/AES keys with the AUTHENTICATE role will encipher the challenge.
    //    b. RSA/ECC keys with the SIGNATURE role will perform signing operations
    //       (on already padded data).
    //    c. SM keys with the KEY_ESTABLISH role will perform the Opacity-ZKM key agreement
    //    All other cases are invalid
    //
    // Pre-conditions:
    // 1) A CHALLENGE is present with data; AND
    // 2) A RESPONSE is present but empty; AND
    // 3) If the key type is ECC and the key has the SECURE_MESSAGE role, it is Variant A
    // 4) If the key type is RSA or ECC and the key has the SIGNATURE role, it is Variant B
    // 5) If the key type is RSA and the key has the KEY_ESTABLISH role, it is Variant C
    // 6) If the key type is TDEA or AES and the key has the AUTHENTICATE role, it is Variant D
    if (challengeOffset != 0
        && challengeLength != 0
        && responseOffset != 0
        && responseLength == 0) {
      /*
      // Variant A - Secure Messaging
      if (key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        if (key instanceof PIVKeyObjectECC) {
          return generalAuthenticateCase1A((PIVKeyObjectECC) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      */
      // Variant B - Digital Signatures
      if (key.hasRole(PIVKeyObject.ROLE_SIGN)) {
        if (key instanceof PIVKeyObjectPKI) {
          return generalAuthenticateCase1B((PIVKeyObjectPKI) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant C - RSA Key Transport
      else if (key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        if (key instanceof PIVKeyObjectRSA) {
          return generalAuthenticateCase1C((PIVKeyObjectRSA) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant D - Symmetric Internal Authentication
      else if (key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
        if (key instanceof PIVKeyObjectSYM) {
          return generalAuthenticateCase1D((PIVKeyObjectSYM) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Invalid case
      else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    } // Continued below

    //
    // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
    //
    // Description:
    // The client presents a CHALLENGE RESPONSE to the CARD, which then verifies it.
    //
    // Pre-conditions:
    // 1) A CHALLENGE is present but empty; AND
    // 2) The key type is SYMMETRIC
    // 3) The key has the AUTHENTICATE role set; AND
    // 4) The key attribute MUTUAL ONLY is not set

    // The client requests a CHALLENGE from the CARD, which returns the CHALLENGE in plaintext
    else if (challengeOffset != 0 && challengeLength == 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase2((PIVKeyObjectSYM) key);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
    //
    // Description:
    // The client presents a CHALLENGE RESPONSE to the CARD, which then verifies it.
    // NOTE: This mode does NOT authenticate the card, just the client.
    //
    // Pre-conditions:
    // 1) A RESPONSE is present with data; AND
    // 2) The key type is SYMMETRIC
    // 3) The key has the AUTHENTICATE role set; AND
    // 4) The key attribute MUTUAL ONLY is not set; AND
    // 5) A successful EXTERNAL AUTHENTICATE REQUEST has immediately preceded this command
    else if (responseOffset != 0 && responseLength != 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase3((PIVKeyObjectSYM) key, responseOffset, responseLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //
    // Description:
    // The client requests a WITNESS (a proof of key posession) from the CARD. The card generates
    // the WITNESS, encrypts it and returns it as ciphertext.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present but empty
    // 2) The key has the AUTHENTICATE role set
    //
    else if (witnessOffset != 0 && witnessLength == 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase4((PIVKeyObjectSYM) key);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //
    // Description:
    // The client decrypts the received WITNESS, generates a CHALLENGE REQUEST and presents both to
    // the CARD. The card verifies the decrypted WITNESS and encrypts the CHALLENGE, which it then
    // returns as the CHALLENGE RESPONSE.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present with data; AND
    // 2) A CHALLENGE is present with data; AND
    // 3) The key type is SYMMETRIC
    // 4) A successful MUTUAL AUTHENTICATE REQUEST has immediately preceded this command
    else if ((witnessOffset != 0)
        && (witnessLength != 0)
        && (challengeOffset != 0)
        && (challengeLength != 0)) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase5(
            (PIVKeyObjectSYM) key, witnessOffset, witnessLength, challengeOffset, challengeLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    }

    //
    // CASE 6 - KEY ESTABLISHMENT SCHEME
    //
    // Description:
    // The client supplies a valid ECC public key and the CARD generates a shared secret key.
    //
    // Pre-Conditions:
    // 1) An EXPONENTIATION parameter is present with data
    // 2) The key type is ECC
    // 3) The key has the KEY_ESTABLISH role
    else if (exponentiationOffset != 0 && (exponentiationLength != 0)) {
      if (key instanceof PIVKeyObjectECC) {
        return generalAuthenticateCase6(
            (PIVKeyObjectECC) key, exponentiationOffset, exponentiationLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    // If any other tag combination is present in the first element of data, it is an invalid case.
    //
    else {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Done
    return ZERO; // Keep compiler happy
  }

  // Variant A - Secure Messaging
  /*
  private short generalAuthenticateCase1A(
      PIVKeyObjectECC key, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state
    authenticateReset();

    // Reset the secure messaging status
    // TODO - Implement Secure Messaging

    return ZERO;
  }
  */

  // Variant B - Digital Signatures
  private short generalAuthenticateCase1B(
      PIVKeyObjectPKI key, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the signature until we do it. Since we could be writing
    // a short-form length (ECC) or long-form (RSA), the TLV header could be either 4 or 8 bytes
    // long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTE:
    // You might be thinking "but if you know the algorithm and key size, you know the length!".
    // You would be right, but unfortunately some implementations put a leading '00' byte in front
    // of their signature data and some don't, so we just wait until we know exactly. It might
    // seem like a pain but it does save an array copy and prevents use of the APDU buffer, so
    // we think it's worth it.
    //

    //
    // MECHANISM CASES:
    // ECC256  - Challenge block is 32 bytes and Signature is 64-70 bytes (single-byte length)
    // ECC384  - Challenge block is 48 bytes and Signature is 96-102 bytes (single-byte length)
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - Given the above cases, if the challenge length is less than 127, we can categorise it
    //   as a TLV short form length.
    // - RSA1024 should not be permitted for this operation, but that should be restricted
    //   using key roles rather than here.

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, challengeLength, CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);

    short offset = writer.getOffset();
    if (challengeLength <= TLV.LENGTH_1BYTE_MAX) {
      // Single-byte form
      offset += TLV.LENGTH_1BYTE;
    } else if (challengeLength <= TLV.LENGTH_2BYTE_MAX) {
      // Double-byte form
      offset += TLV.LENGTH_2BYTE;
    } else {
      // Triple-byte form
      offset += TLV.LENGTH_3BYTE;
    }

    // Sign the CHALLENGE data to the location specified by 'offset'
    short length;
    try {
      length = key.sign(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (Exception e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written, so
    // we can write the length
    //

    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    // Now we can move past the signature data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  // Variant C - RSA Key Transport
  private short generalAuthenticateCase1C(
      PIVKeyObjectRSA key, short challengeOffset, short challengeLength) throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the data until we do it. Since we could be writing
    // a short-form length (ECC) or long-form (RSA), the TLV header could be either 4 or 8 bytes
    // long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTE:
    // You might be thinking "but if you know the algorithm and key size, you know the length!".
    // You would be right, but unfortunately some implementations put a leading '00' byte in front
    // of their signature data and some don't, so we just wait until we know exactly. It might
    // seem like a pain but it does save an array copy and prevents use of the APDU buffer, so
    // we think it's worth it.
    //

    //
    // MECHANISM CASES:
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - ECC keys are not valid for this case

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, challengeLength, CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);

    short offset = writer.getOffset();
    if (challengeLength <= TLV.LENGTH_1BYTE_MAX) {
      // Single-byte form
      offset += TLV.LENGTH_1BYTE;
    } else if (challengeLength <= TLV.LENGTH_2BYTE_MAX) {
      // Double-byte form
      offset += TLV.LENGTH_2BYTE;
    } else {
      // Triple-byte form
      offset += TLV.LENGTH_3BYTE;
    }

    // Decrypt the CHALLENGE data
    short length;
    try {
      length = key.keyAgreement(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (Exception e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written, so
    // we can write the length
    //
    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    // Now we can move past the decrypted data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  // Variant E - Symmetric Internal Authentication
  private short generalAuthenticateCase1D(
      PIVKeyObjectSYM key, short challengeOffset, short challengeLength) throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key MUST have the PERMIT INTERNAL attribute set
    if (key.hasAttribute(PIVKeyObject.ATTR_PERMIT_INTERNAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    //

    // Write out the response TLV, passing through the challenge length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, challengeLength, CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);

    // Encrypt the CHALLENGE data
    short offset = writer.getOffset();
    try {
      offset += key.encrypt(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (Exception e) {
      authenticateReset();

      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Finalise the TLV object and get the entire data object length
    writer.setOffset(offset);
    short length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase2(PIVKeyObjectSYM key) throws ISOException {

    //
    // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
    // Authenticates the HOST to the CARD
    //

    // > Client application requests a challenge from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Clear any existing authentication state
    cspPIV.clearAuthenticatedKey();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the AUTHENTICATE role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT EXTERNAL attribute set
    if (key.hasAttribute(PIVKeyObject.ATTR_PERMIT_EXTERNAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short length = key.getBlockLength();

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, length, CONST_TAG_AUTH_TEMPLATE);

    // Create the CHALLENGE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE);
    writer.writeLength(key.getBlockLength());

    // Generate the CHALLENGE data and write it to the output buffer
    short offset = writer.getOffset();
    PIVCrypto.doGenerateRandom(scratch, offset, length);

    try {
      // Generate and store the encrypted CHALLENGE in our context, so we can compare it without
      // the key reference later.
      offset += key.encrypt(scratch, offset, length, authenticationContext, OFFSET_AUTH_CHALLENGE);
    } catch (Exception e) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set our authentication state to EXTERNAL
    authenticationContext[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;
    authenticationContext[OFFSET_AUTH_ID] = key.getId();
    authenticationContext[OFFSET_AUTH_MECHANISM] = key.getMechanism();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase3(
      PIVKeyObjectSYM key, short responseOffset, short responseLength) throws ISOException {

    //
    // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
    //

    // > Client application responds to a challenge from the PIV Card Application.

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is EXTERNAL
    if (authenticationContext[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The RESPONSE tag length must be the same as our block length
    if (responseLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (Util.arrayCompare(
            scratch, responseOffset, authenticationContext, OFFSET_AUTH_CHALLENGE, responseLength)
        != 0) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // We are now authenticated. Set the key's security status
    cspPIV.setAuthenticatedKey(key.getId());

    // Reset our authentication state
    authenticateReset();
    PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);

    // Done, no data to return
    return ZERO;
  }

  private short generalAuthenticateCase4(PIVKeyObjectSYM key) throws ISOException {

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //

    // > Client application requests a WITNESS from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Clear any existing authentication state
    cspPIV.clearAuthenticatedKey();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT MUTUAL attribute set
    if (key.hasAttribute(PIVKeyObject.ATTR_PERMIT_MUTUAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // < PIV Card Application returns a WITNESS that is created by generating random
    //   data and encrypting it using the referenced key

    // Generate a block length worth of WITNESS data
    short length = key.getBlockLength();
    PIVCrypto.doGenerateRandom(authenticationContext, OFFSET_AUTH_CHALLENGE, length);

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, length, CONST_TAG_AUTH_TEMPLATE);

    // Create the WITNESS tag
    writer.writeTag(CONST_TAG_AUTH_WITNESS);
    writer.writeLength(length);

    // Encrypt the WITNESS data and write it to the output buffer
    short offset = writer.getOffset();
    offset += key.encrypt(authenticationContext, OFFSET_AUTH_CHALLENGE, length, scratch, offset);
    writer.setOffset(offset); // Update the TLV offset value

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Update our authentication status, id and mechanism
    authenticationContext[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    authenticationContext[OFFSET_AUTH_ID] = key.getId();
    authenticationContext[OFFSET_AUTH_MECHANISM] = key.getMechanism();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase5(
      PIVKeyObjectSYM key,
      short witnessOffset,
      short witnessLength,
      short challengeOffset,
      short challengeLength)
      throws ISOException {

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //

    //
    // PRE-CONDITIONS
    //

    // < PIV Card Application authenticates the client application by verifying the decrypted
    // witness.

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is MUTUAL
    if (authenticationContext[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The WITNESS tag length must be the same as our block length
    if (witnessLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The CHALLENGE tag length must be equal to the witness length
    if (challengeLength != witnessLength) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (Util.arrayCompare(
            scratch, witnessOffset, authenticationContext, OFFSET_AUTH_CHALLENGE, witnessLength)
        != 0) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: The WITNESS is now verified, on to the CHALLENGE

    // > Client application requests encryption of CHALLENGE data from the card using the
    // > same key.

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, challengeLength, CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);
    short offset = writer.getOffset();

    // Encrypt the CHALLENGE data
    offset += key.encrypt(scratch, challengeOffset, challengeLength, scratch, offset);

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    short length = writer.finish();

    // Set this key's authentication state
    cspPIV.setAuthenticatedKey(key.getId());

    // Clear our authentication state
    authenticateReset();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // < PIV Card Application indicates successful authentication and sends back the encrypted
    // challenge.
    return length;
  }

  private short generalAuthenticateCase6(
      PIVKeyObjectECC key, short exponentiationOffset, short exponentiationLength)
      throws ISOException {

    //
    // CASE 6 - EXPONENTIATION AUTHENTICATE RESPONSE
    //

    // > Client application returns the ECDH derived shared secret

    // Reset any other authentication intermediate state
    authenticateReset();

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The EXPONENTIATION tag length must be the same as our block length
    // TODO: Should put this into the PIVKeyObjectECC class
    short length = (short) (key.getBlockLength() * (short) 2 + (short) 1);
    if (exponentiationLength != length) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, length, CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(key.getKeyLengthBytes());

    // Compute the shared secret
    length =
        key.keyAgreement(
            scratch, exponentiationOffset, exponentiationLength, scratch, writer.getOffset());

    // Move to the end of the key agreement output data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // < PIV Card Application indicates successful authentication and sends back the encrypted
    // challenge.
    return length;
  }

  /**
   * The GENERATE ASYMMETRIC KEY PAIR card command initiates the generation and storing in the card
   * of the reference data of an asymmetric key pair, i.e., a public key and a private key. The
   * public key of the generated key pair is returned as the response to the command. If there is
   * reference data currently associated with the key reference, it is replaced in full by the
   * generated data.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The offset of the CDATA element
   * @return The length of the return data
   */
  short generateAsymmetricKeyPair(byte[] buffer, short offset) throws ISOException {

    // Request Elements
    final byte CONST_TAG_TEMPLATE = (byte) 0xAC;
    final byte CONST_TAG_MECHANISM = (byte) 0x80;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'TEMPLATE' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_TEMPLATE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Skip the length byte
    offset++;

    // PRE-CONDITION 2 - The 'MECHANISM' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 3 - The 'MECHANISM' tag must have a length of 1
    if (buffer[offset++] != (short) 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // NOTE: We ignore the existence of the 'PARAMETER' tag, because according to SP800-78-4 the
    // RSA public exponent is now fixed to 65537 (Section 3.1 PIV Cryptographic Keys).
    // ECC keys have no parameter.

    // PRE-CONDITION 4A - The key reference and mechanism must exist (key test)
    if (!cspPIV.keyExists(buffer[ISO7816.OFFSET_P2])) {
      // The key reference is bad
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 4B - The key reference and mechanism must exist (mechanism test)
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[offset]);
    if (key == null) {
      // NOTE: The error message we return here is different dependant on whether the key is bad
      // (6A86), or the mechanism is bad (6A80) (See SP800-73-4 3.3.2 Generate Asymmetric Key pair).
      // The mechanism is bad
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 5 - The key must be an asymmetric key (key pair)
    if (!(key instanceof PIVKeyObjectPKI)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep static analyser happy
    }

    // PRE-CONDITION 6 - The access rules must be satisfied for administrative access
    if (!cspPIV.checkAccessModeAdmin(key)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Generate the key pair
    PIVKeyObjectPKI keyPair = (PIVKeyObjectPKI) key;
    short length = keyPair.generate(scratch, ZERO);

    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of the object we are writing back
    return length;
  }

  private static final byte PIN_PADDING_BYTE = (byte) 0xFF;

  private boolean verifyPinRules(byte[] buffer, short offset, short length) {

    boolean passed = true;
    //
    // RULE 1 - SEQUENCE RULE (Ascending and Descending)
    //
    byte ruleSequence = config.readValue(Config.CONFIG_PIN_RULE_SEQUENCE);
    if (ruleSequence > (byte) 0) {
      byte last = (byte) 0;
      byte ascendingCount = (byte) 1;
      byte descendingCount = (byte) 1;
      byte maxAscending = (byte) 0;
      byte maxDescending = (byte) 0;

      for (short i = 0; i < length; i++) {

        byte value = buffer[(short) (offset + i)];

        // If we have reached padding bytes, we are done checking
        if (value == PIN_PADDING_BYTE) break;

        // HACK: We make use of the fact that the ASCII value 0h is not possible
        // for a PIN value.

        // ASCENDING TALLY
        if (last != (byte) 0 && (byte) (last + (byte) 1) == value) {
          ascendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
          ascendingCount = (byte) 1;
        }

        // DESCENDING TALLY
        if (last != (byte) 0 && (byte) (last - (byte) 1) == value) {
          descendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;
          descendingCount = (byte) 1;
        }

        last = value;
      }

      // Track our final counts
      maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
      maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;

      if (maxAscending >= ruleSequence || maxDescending >= ruleSequence) passed = false;
    }

    //
    // RULE 2 - DISTINCTIVENESS RULE
    //
    // If the distinctiveness rule applies (n > 0) then a PIN is rejected if any single character
    // is re-used more than [n] times.
    //

    byte ruleDistinct = config.readValue(Config.CONFIG_PIN_RULE_DISTINCT);
    if (ruleDistinct > (byte) 0) {
      byte maxSingle = (byte) 0;

	  short end = (short)(offset + length);	  
      for (short i = offset; i < end; i++) {
        byte count = (byte) 1; // Every used digit has at least 1
        for (short j = (short) (i + (short) 1); j < end; j++) {
          // If we have a padding byte, we are done checking for this digit
          if (buffer[i] == PIN_PADDING_BYTE) break;
          if (buffer[i] == buffer[j]) count++;
        }
        maxSingle = (count > maxSingle) ? count : maxSingle;
      }

      if (maxSingle >= ruleDistinct) passed = false;
    }

    // Done
    return passed;
  }

  /**
   * Performs data validation on an incoming PIN number to ensure that it conforms to SP800-73-4
   * Part 2 - Authentication of an Individual
   *
   * @param buffer The buffer containing the PIN
   * @param offset The offset of the PIN data
   * @param length The length of the PIN data
   * @return True if the supplied PIN conforms to the format requirements
   */
  private boolean verifyPinFormat(byte[] buffer, short offset, short length) throws ISOException {

    // The amount to add to convert upper-case to lower-case
    final byte CONST_ALPHA_CASE_DELTA = (byte) 32;

    // The pairing code shall be exactly 8 bytes in length and the PIV Card Application
    // PIN shall be between 6 and 8 bytes in length. If the actual length of PIV Card Application
    // PIN is less than 8 bytes it shall be padded to 8 bytes with 'FF' when presented to the card
    // command interface. The 'FF' padding bytes shall be appended to the actual value of the PIN.

    // NOTE: We define the minimum and maximum lengths in configuration, but only the max is checked
    //		 here because of the padding requirement
    byte minLength = config.readValue(Config.CONFIG_PIN_MIN_LENGTH);
    byte maxLength = config.readValue(Config.CONFIG_PIN_MAX_LENGTH);
    if (length != maxLength) {
      return false;
    }

    // The bytes comprising the PIV Card Application PIN and pairing code shall be limited to values
    // 0x30-0x39, the ASCII values for the decimal digits '0'-'9'. For example,
    // 		+ Actual PIV Card Application PIN: '123456' or '31 32 33 34 35 36'
    //		+ Padded PIV Card Application PIN presented to the card command interface:
    //        '31 32 33 34 35 36 FF FF'

    // The PIV Card Application shall enforce the minimum length requirement of six bytes for the
    // PIV Card Application PIN (i.e., shall verify that at least the first six bytes of the value
    // presented to the card command interface are in the range 0x30-0x39) as well as the other
    // formatting requirements specified in this section.

    // If the Global PIN is used by the PIV Card Application, then the above encoding, length,
    // padding, and enforcement of minimum PIN length requirements for the PIV Card Application
    // PIN shall apply to the Global PIN.

    //
    // NOTES:
    // - OpenFIPS201 permits the following PIN character sets
    //   - Default (digits 0 to 9, PIV compliant)
    //	 - Alpha Case Variant (all printable ascii characters, not PIV compliant)
    //	 - Alpha Case Invariant (all printable ascii characters, case insensitive, not PIV compliant)
    //	 - Raw (All possible values 0 to 255, same as PUK)

    byte minPermitted;
    byte maxPermitted;
    boolean invariant = false;

    switch (config.readValue(Config.CONFIG_PIN_CHARSET)) {
      case Config.PIN_CHARSET_ALPHA:
        minPermitted = ' '; // 20h
        maxPermitted = '~'; // 7Eh
        break;
      case Config.PIN_CHARSET_ALPHA_INVARIANT:
        minPermitted = ' '; // 20h
        maxPermitted = '~'; // 7Eh
        invariant = true;
        break;
      case Config.PIN_CHARSET_RAW:
        // No further processing required
        return true;

      case Config.PIN_CHARSET_NUMERIC:
      default:
        minPermitted = '0'; // 30h
        maxPermitted = '9'; // 39h
        break;
    }

    boolean padding = false;
    for (short i = 0; i < length; i++) {
      if (padding) {
        // Once we have reached padding, all subsequent characters must be padding
        if (buffer[offset] != PIN_PADDING_BYTE) return false;
      } else {
        // Check if we have reached our padding
        if (buffer[offset] == PIN_PADDING_BYTE) {
          if (i < minLength) {
            // RULE: The minimum PIN length has not been reached
            return false;
          } else {
            padding = true;
          }
        } else {

          // Invariant Check
          // NOTE: This converts the input buffer to all lower-case, which will then
          // ensure it matches the actual PIN value.
          if (invariant && buffer[offset] >= 'A' && buffer[offset] <= 'Z') {
            buffer[offset] |= CONST_ALPHA_CASE_DELTA;
          }

          // Range Check
          if (buffer[offset] < minPermitted || buffer[offset] > maxPermitted) {
            // RULE: The PIN character does not fall in the permissable range
            return false;
          }
        }
      }

      offset++;
    }

    // We got this far, passed!
    return true;
  }

  ///////////////////////////////////////////////////////////////////////////
  //
  // CARD MANAGEMENT METHODS
  //
  // The following methods putDataAdmin() and changeReferenceDataAdmin() are
  // not defined in NIST SP800-73-4 because the PIV standard does not define
  // a mechanism for a number of card management functions, such as:
  //
  // - Setting the default PIN or PUK values
  // - Symmetric Key Injection
  // - Optional asymmetric key injection
  // - Defining applet lifecycle and configuration parameters
  //
  ///////////////////////////////////////////////////////////////////////////

  private static final byte CONST_TAG_LEGACY_OPERATION = (byte) 0x8A; // Legacy
  private static final byte CONST_TAG_ID = (byte) 0x8B;
  private static final byte CONST_TAG_MODE_CONTACT = (byte) 0x8C;
  private static final byte CONST_TAG_MODE_CONTACTLESS = (byte) 0x8D;
  private static final byte CONST_TAG_ADMIN_KEY = (byte) 0x91;
  private static final byte CONST_TAG_KEY_MECHANISM = (byte) 0x8E;
  private static final byte CONST_TAG_KEY_ROLE = (byte) 0x8F;
  private static final byte CONST_TAG_KEY_ATTRIBUTE = (byte) 0x90;

  private static final byte CONST_TAG_LEGACY = (byte) 0x30;
  private static final byte CONST_TAG_CREATE_OBJECT = (byte) 0x64;
  private static final byte CONST_TAG_DELETE_OBJECT = (byte) 0x65;
  private static final byte CONST_TAG_CREATE_KEY = (byte) 0x66;
  private static final byte CONST_TAG_DELETE_KEY = (byte) 0x67;
  private static final byte CONST_TAG_UPDATE_CONFIG = (byte) 0x68;
  private static final byte CONST_TAG_BULK_REQUEST = (byte) 0x6A;

  private void processCreateObjectRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    //
    // IMPLEMENTATION NOTE:
    // We are progressing through to supporting multi-byte definition of data objects, so until
    // this is fully completed, we will accept 1-3 byte length identifiers and just use the final
    // byte as the identifier. This means if you pass through '5FC101' and '6FC101' it will fail
    // until we support the 3-bytes internally.
    //

    // PRE-CONDITION 2 - The 'ID' tag have length between 1 and 3
    short idLength = reader.getLength();
    if (idLength < (short) 1 || idLength > (short) 3) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }

    // Use the last byte of the value as the identifier
    short offset = reader.getDataOffset();
    offset += reader.getLength();
    offset--;
    byte id = scratch[offset];
    reader.moveNext();

    // PRE-CONDITION 3 - The 'MODE CONTACT' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACT)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'MODE CONTACT' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
      return;
    }

    byte modeContact = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5 - The 'MODE CONTACTLESS' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
      return;
    }

    // PRE-CONDITION 6 - The 'MODE CONTACTLESS' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
      return;
    }

    byte modeContactless = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 7 - The 'ADMIN KEY' tag MAY be present
    byte adminKey = (byte) 0;
    if (reader.match(CONST_TAG_ADMIN_KEY)) {

      // PRE-CONDITION 8 - If the 'ADMIN KEY' tag is present, it MUST be length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(PIV.SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH);
        return;
      }

      adminKey = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 9 - The object referenced by 'id' value must not exist in the data store.
    PIVObject obj = firstDataObject;
    while (obj != null) {
      if (obj.getId() == id) ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
      obj = obj.nextObject;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Create our new key
    PIVDataObject dataObject = new PIVDataObject(id, modeContact, modeContactless, adminKey);

    // STEP 2 - Add it to our linked list
    // NOTE: If this is the first key added, just set our firstKey. Otherwise add it to the head
    // to save a traversal (inspired by having no good answer to Steve Paik's question why we
    // add it to the end).
    if (firstDataObject == null) {
      firstDataObject = dataObject;
    } else {
      // Insert at the head of the list
      dataObject.nextObject = firstDataObject;
      firstDataObject = dataObject;
    }
  }

  private void processDeleteObjectRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    //
    // IMPLEMENTATION NOTE:
    // We are progressing through to supporting multi-byte definition of data objects, so until
    // this is fully completed, we will accept 1-3 byte length identifiers and just use the final
    // byte as the identifier. This means if you pass through '5FC101' and '6FC101' it will fail
    // until we support the 3-bytes internally.
    //

    // PRE-CONDITION 2 - The 'ID' tag have length between 1 and 3
    short idLength = reader.getLength();
    if (idLength < (short) 1 || idLength > (short) 3) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }

    // Use the last byte of the value as the identifier
    short offset = reader.getDataOffset();
    offset += reader.getLength();
    offset--;
    byte id = scratch[offset];
    reader.moveNext();

    // PRE-CONDITION 7 - The object referenced by 'id' value MUST exist in the data store.
    PIVObject obj = firstDataObject;
    boolean objectFound = false;
    while (obj != null) {
      if (obj.getId() == id) objectFound = true;
      obj = obj.nextObject;
    }
    if (!objectFound) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Delete the data object
    // TODO - Implement data object deletion
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  private void processCreateKeyRequest(TLVReader reader, boolean legacy) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }
    byte id = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 3 - The 'MODE CONTACT' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACT)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'MODE CONTACT' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
      return;
    }

    byte modeContact = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5 - The 'MODE CONTACTLESS' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
      return;
    }

    // PRE-CONDITION 6 - The 'MODE CONTACTLESS' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
      return;
    }

    byte modeContactless = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 7 - The 'ADMIN KEY' tag MAY be present
    byte adminKey = (byte) 0;
    if (reader.match(CONST_TAG_ADMIN_KEY)) {

      // PRE-CONDITION 8 - If the 'ADMIN KEY' tag is present, it MUST be length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(PIV.SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH);
        return;
      }

      adminKey = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 9 - The 'KEY MECHANISM' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_MECHANISM)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_MISSING);
      return;
    }

    // PRE-CONDITION 10 - The 'KEY MECHANISM' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH);
      return;
    }
    byte keyMechanism = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 11 - The supplied mechanism must be supported by this instance
    if (!PIVCrypto.supportsMechanism(keyMechanism)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION 12 - The 'KEY ROLE' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_ROLE)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ROLE_MISSING);
      return;
    }

    // PRE-CONDITION 13 - The 'KEY ROLE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH);
      return;
    }
    byte keyRole = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 14 - The 'KEY ATTRIBUTE' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_ATTRIBUTE)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ATTR_MISSING);
      return;
    }

    // PRE-CONDITION 15 - The 'KEY ATTRIBUTE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH);
      return;
    }
    byte keyAttribute = reader.toByte();
    reader.moveNext();

    if (config.readFlag(Config.OPTION_RESTRICT_SINGLE_KEY)) {
      // PRE-CONDITION 16A - If CONFIG.RESTRICT_SINGLE_KEY is set, the key referenced by the
      // 'id' and 'mechanism' pair MUST NOT exist in the key store.
      if (cspPIV.keyExists(id)) {
        ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
        return;
      }
    } else {
      // PRE-CONDITION 16B - If CONFIG.RESTRICT_SINGLE_KEY is NOT set, the key referenced by
      // the 'id' and 'mechanism' pair MUST NOT exist in the key store.
      if (cspPIV.selectKey(id, keyMechanism) != null) {
        ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
        return;
      }
    }

    //
    // EXECUTION STEPS
    //
    
    // STEP 1 - If this is a legacy request, apply the PERMIT_MUTUAL
    // key attribute as a default. 
    if (legacy && PIVCrypto.isSymmetricMechanism(keyMechanism)) {
	   keyAttribute |= PIVKeyObject.ATTR_PERMIT_MUTUAL;
    }

    // STEP 2 - Add the key to the key store
    cspPIV.createKey(
        id, modeContact, modeContactless, adminKey, keyMechanism, keyRole, keyAttribute);
  }

  private void processDeleteKeyRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }
    byte id = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 3 - The 'KEY MECHANISM' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_MECHANISM)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'KEY MECHANISM' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH);
      return;
    }
    byte keyMechanism = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5 - the key referenced by the 'id' and 'mechanism' pair MUST exist
    if (cspPIV.selectKey(id, keyMechanism) == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - If the key is related to any SM session or authenticated session, clear it

    // STEP 2 - Delete the key from the key store

    // TODO - Implement key deletion
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  /**
   * This is the administrative equivalent for the PUT DATA card and is intended for use by Card
   * Management Systems to generate the on-card file-system.
   *
   * @param buffer - The incoming APDU buffer
   * @param offset - The starting offset of the CDATA section
   * @param length - The length of the CDATA section
   */
  void putDataAdmin(byte[] buffer, short offset, short length) throws ISOException {

    //
    // SECURITY PRE-CONDITION
    //

    // The command must have been sent over SCP with CEnc+CMac
    if (!cspPIV.getIsSecureChannel()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming command. Keep in mind that
    // the original buffer still contains the APDU header.

    // Initialise our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    //
    // PRE-PROCESSING
    //

    // If the top-level tag indicates this is a BULK request, we move into it and then we are left
    // with an array of objects. If it doesn't, we are already at the start of the only request.
    boolean isBulk;
    if (reader.match(CONST_TAG_BULK_REQUEST)) {
      isBulk = true;
      reader.moveInto();
    } else {
      isBulk = false;
    }

    final byte CONST_OP_LEGACY_DATA = (byte) 0x01;
    final byte CONST_OP_LEGACY_KEY = (byte) 0x02;

    // Loop through all the requests
    do {
      // Get the operation value
      byte operation = reader.getTag();

      // PRE-CONDITION 1 - The tag must be constructed
      if (!reader.isConstructed()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return;
      }

      // Move into the constructed tag
      reader.moveInto();

      //
      // LEGACY SUPPORT:
      // To minimise impact on issuance systems, we will continue to support the legacy PUT DATA
      // ADMIN format until we decide it isn't needed anymore.
      // There are limitations:
      // - The legacy format can only create data objects and keys, not update configuration
      // - This means only the default applet settings will apply (NIST compliant profile)
      //
      boolean legacy = false;
      if (operation == CONST_TAG_LEGACY) {
        // PRE-CONDITION 2A - If this is a LEGACY operation, the 'LEGACY OPERATION' tag MUST
        // be present
        if (!reader.match(CONST_TAG_LEGACY_OPERATION)) {
          ISOException.throwIt(PIV.SW_PUT_DATA_OP_MISSING);
        }
        // PRE-CONDITION 2B - The 'OPERATION' tag MUST have length 1
        if (reader.getLength() != (short) 1) {
          ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
        }

        // Update the operation and move on
        legacy = true;
        operation = reader.toByte();
        reader.moveNext();
      }

      switch (operation) {

          // Create a data object record
        case CONST_OP_LEGACY_DATA:
        case CONST_TAG_CREATE_OBJECT:
          processCreateObjectRequest(reader);
          break;

        case CONST_TAG_DELETE_OBJECT:
          processDeleteObjectRequest(reader);
          break;

          // Create a key object record
        case CONST_OP_LEGACY_KEY:
        case CONST_TAG_CREATE_KEY:
          processCreateKeyRequest(reader, legacy);
          break;

        case CONST_TAG_DELETE_KEY:
          processDeleteKeyRequest(reader);
          break;

          // Update one or more configuration parameters
        case CONST_TAG_UPDATE_CONFIG:
          config.update(reader);
          break;

        default:
          ISOException.throwIt(SW_PUT_DATA_OP_INVALID_VALUE);
          return;
      }

      // If this is a bulk operation,
    } while (isBulk && !reader.isEOF());
  }

  /**
   * This method is the equivalent of the CHANGE REFERENCE DATA command, however it is intended to
   * operate on key references that are NOT listed in SP800-37-4. This is the primary method by
   * which administrative key references are updated and is intended to fill in the gap in PIV that
   * does not cover how pre-personalisation is implemented.
   *
   * @param id The target key / pin reference being changed
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   *     <p>The main differences to CHANGE REFERENCE DATA are: - It supports updating any key
   *     reference that is not covered by CHANGE REFERENCE DATA already - It requires a global
   *     platform secure channel to be operating with the CEncDec attribute (encrypted) - It does
   *     NOT require the old value to be supplied in order to change a key - It also supports
   *     updating the PIN/PUK values, without requiring knowledge of the old value
   */
  void changeReferenceDataAdmin(byte id, byte[] buffer, short offset, short length)
      throws ISOException {

    final byte CONST_TAG_SEQUENCE = (byte) 0x30;

    // The PIV Card Application may allow the reference data associated with other key references
    // to be changed by the PIV Card Application CHANGE REFERENCE DATA, if PIV Card Application will
    // only perform the command with other key references if the requirements specified in Section
    // 2.9.2 of FIPS 201-2 are satisfied.

    //
    // SECURITY PRE-CONDITION
    //

    // The command must have been sent over SCP with CEnc+CMac
    if (!cspPIV.getIsSecureChannel()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer
    // still contains the APDU header.

    //
    // SPECIAL CASE 1 - LOCAL PIN
    //
    if (id == ID_CVM_LOCAL_PIN) {
      // NOTE:
      // We deliberately ignore the value of CONFIG_PIN_ENABLE_LOCAL here as there may be a good
      // reason for setting a pre-defined PIN value with the anticipation of enabling it later

      if (!verifyPinFormat(scratch, ZERO, length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      if (!verifyPinRules(scratch, ZERO, length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      // Update the PIN
      // NOTE: We ignore the history check here since this is an administrative update
      cspPIV.updatePIN(ID_CVM_LOCAL_PIN, scratch, ZERO, (byte) length, ZERO);
      return; // Done
    }

    //
    // SPECIAL CASE 2 - PUK
    //
    if (id == ID_CVM_PUK) {
      // NOTE: No format verification required for the PUK

      // Update the PUK
      cspPIV.updatePIN(ID_CVM_PUK, scratch, ZERO, (byte) length, ZERO);

      return; // Done
    }

    // PRE-CONDITION 1 - The key reference and mechanism MUST point to an existing key
    PIVKeyObject key = cspPIV.selectKey(id, buffer[ISO7816.OFFSET_P1]);
    if (key == null) {
      // If any key reference value is specified that is not supported by the card, the PIV Card
      // Application shall return the status word '6A 88'.
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 2 - The key object MUST have the ATTR_IMPORTABLE attribute
    if (!key.hasAttribute(PIVKeyObject.ATTR_IMPORTABLE)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return; // Keep static analyser happy
    }

    // Set up our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    // PRE-CONDITION 3 - The parent tag MUST be of type SEQUENCE
    if (!reader.match(CONST_TAG_SEQUENCE)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 4 - The SEQUENCE length MUST be smaller than the APDU data length
    if (reader.getLength() > length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // Move to the child tag
    reader.moveInto();

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Update the relevant key element
    key.updateElement(reader.getTag(), scratch, reader.getDataOffset(), reader.getLength());
  }

  private short processGetVersion(TLVWriter writer) {

    final byte CONST_TAG_APPLICATION = (byte) 0x80;
    final byte CONST_TAG_MAJOR = (byte) 0x81;
    final byte CONST_TAG_MINOR = (byte) 0x82;
    final byte CONST_TAG_REVISION = (byte) 0x83;
    final byte CONST_TAG_DEBUG = (byte) 0x84;

    // Application
    writer.write(
        CONST_TAG_APPLICATION, Config.APPLICATION_NAME, ZERO, Config.LENGTH_APPLICATION_NAME);

    // Major
    writer.write(CONST_TAG_MAJOR, Config.VERSION_MAJOR);

    // Minor
    writer.write(CONST_TAG_MINOR, Config.VERSION_MINOR);

    // Revision
    writer.write(CONST_TAG_REVISION, Config.VERSION_REVISION);

    // Debug
    writer.write(CONST_TAG_DEBUG, Config.VERSION_DEBUG);

    return writer.finish();
  }

  private short processGetStatus(TLVWriter writer) {

    final byte CONST_TAG_APPLET_STATE = (byte) 0x80;
    final byte CONST_TAG_PIN_VERIFIED = (byte) 0x81;
    final byte CONST_TAG_PIN_ALWAYS = (byte) 0x82;
    final byte CONST_TAG_SM_STATE = (byte) 0x83;
    final byte CONST_TAG_VCI_STATE = (byte) 0x84;
    final byte CONST_TAG_SCP_STATE = (byte) 0x85;
    final byte CONST_TAG_CONTACTLESS = (byte) 0x86;
    final byte CONST_TAG_FIPS_MODE = (byte) 0x87;

    // TODO: Additional status items
    // # of keys defined
    // # of keys initialised
    // # of data objects defined
    // # of data objects initialised
    // PIN retries remaining
    // PIN retries total
    // PIN always status
    // PUK retries remaining
    // PUK retries total
    // Total volatile memory
    // Available volatile memory
    // Total non-volatile memory
    // Available non-volatile memory

    // Applet State
    writer.write(CONST_TAG_APPLET_STATE, (byte) 0); // TODO

    // PIN Verified
    writer.write(CONST_TAG_PIN_VERIFIED, cspPIV.getIsPINVerified() ? (byte) 1 : (byte) 0);

    // PIN Always
    writer.write(CONST_TAG_PIN_ALWAYS, cspPIV.getIsPINAlways() ? (byte) 1 : (byte) 0);

    // SM State
    writer.write(CONST_TAG_SM_STATE, (byte) 0); // TODO

    // VCI State
    writer.write(CONST_TAG_VCI_STATE, (byte) 0); // TODO

    // SCP State
    writer.write(CONST_TAG_SCP_STATE, cspPIV.getIsSecureChannel() ? (byte) 1 : (byte) 0);

    // Contactless
    writer.write(CONST_TAG_CONTACTLESS, cspPIV.getIsContactless() ? (byte) 1 : (byte) 0);

    // FIPS Mode
    writer.write(CONST_TAG_FIPS_MODE, (byte) 0); // TODO

    return writer.finish();
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   * @return The length of the entire data object
   */
  short getDataExtended(byte[] buffer, short offset, short length) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final short CONST_LEN = (short) 3;
    final byte CONST_TAG_EXTENDED = (byte) 0x2F;

    final byte CONST_TAG_DATA = (byte) 0x53;

    final short CONST_DO_GET_VERSION = (short) 0x4756; // GV
    final short CONST_DO_GET_STATUS = (short) 0x4753; // GS
    // final short CONST_DO_GET_CONFIG = (short) 0x4743; // GC
    // final short CONST_DO_GET_FIRST_DO = (short) 0x4644; // FD
    // final short CONST_DO_GET_NEXT_DO = (short) 0x4E44; // ND
    // final short CONST_DO_GET_FIRST_KEY = (short) 0x464B; // FK
    // final short CONST_DO_GET_NEXT_KEY = (short) 0x4E4B; // NK

    //
    // PRE-CONDITIONS
    //

    // Copy the APDU buffer to the scratch buffer so that we can reference it with our TLVReader
    Util.arrayCopyNonAtomic(buffer, offset, scratch, ZERO, length);
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    // PRE-CONDITION 1 - The 'TAG' data element must be present
    if (!reader.match(CONST_TAG)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 2 - The 'TAG' data element must be the correct length
    if (reader.getLength() != CONST_LEN) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // PRE-CONDITION 2 - The 'TAG' value must start with CONST_TAG_EXTENDED
    if (!reader.matchData(CONST_TAG_EXTENDED)) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // Retrieve the 2-byte extended data identifier
    offset = reader.getDataOffset();
    offset++; // Move to the 2nd data byte
    short id = Util.getShort(scratch, offset);

    //
    // EXECUTION
    //
    // NOTE:
    // An assumption is made here that all responses can fit within a short length TLV object
    // so we put a sanity check at the end to make sure this is the case.
    //
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, TLV.LENGTH_1BYTE_MAX, CONST_TAG_DATA);

    switch (id) {
      case CONST_DO_GET_VERSION:
        length = processGetVersion(writer);
        break;

      case CONST_DO_GET_STATUS:
        length = processGetStatus(writer);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        return (0); // Keep static analyser happy
    }

    // Length sanity check (I should never construct a length larger than a short length)
    if (length > TLV.LENGTH_1BYTE_MAX) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // STEP 1 - Set up the outgoing chainbuffer
    chainBuffer.setOutgoing(scratch, ZERO, length, false);

    // Done - return how many bytes we will process
    return length;
  }

  /**
   * Searches for a data object within the local data store
   *
   * @param id The data object to find
   * @return The relevant data object instance, or null if none was found.
   */
  private PIVDataObject findDataObject(byte id) {

    PIVDataObject data = firstDataObject;

    // Traverse the linked list
    while (data != null) {
      if (data.match(id)) {
        return data;
      }

      data = (PIVDataObject) data.nextObject;
    }

    return null;
  }
}
