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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import org.globalplatform.GPSystem;

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
public final class PIV {

  //
  // Persistent Objects
  //

  // Transient buffer allocation
  public static final short LENGTH_SCRATCH = (short) 284;

  //
  // Static PIV identifiers
  //

  // Data Objects
  public static final byte ID_DATA_DISCOVERY = (byte) 0x7E;

  // Keys
  public static final byte ID_ALG_DEFAULT = (byte) 0x00; // This maps to TDEA_3KEY
  public static final byte ID_ALG_TDEA_3KEY = (byte) 0x03;
  public static final byte ID_ALG_RSA_1024 = (byte) 0x06;
  public static final byte ID_ALG_RSA_2048 = (byte) 0x07;
  public static final byte ID_ALG_AES_128 = (byte) 0x08;
  public static final byte ID_ALG_AES_192 = (byte) 0x0A;
  public static final byte ID_ALG_AES_256 = (byte) 0x0C;
  public static final byte ID_ALG_ECC_P256 = (byte) 0x11;
  public static final byte ID_ALG_ECC_P384 = (byte) 0x14;
  public static final byte ID_ALG_ECC_CS2 = (byte) 0x27; // Secure Messaging - ECCP256+SHA256
  public static final byte ID_ALG_ECC_CS7 = (byte) 0x2E; // Secure Messaging - ECCP384+SHA384

  // Verification Methods
  public static final byte ID_KEY_GLOBAL_PIN = (byte) 0x00;
  public static final byte ID_KEY_PIN = (byte) 0x80;
  public static final byte ID_KEY_PUK = (byte) 0x81;

  // General Authenticate Tags
  public static final byte CONST_TAG_AUTH_TEMPLATE = (byte) 0x7C;
  public static final byte CONST_TAG_AUTH_WITNESS = (byte) 0x80;
  public static final byte CONST_TAG_AUTH_CHALLENGE = (byte) 0x81;
  public static final byte CONST_TAG_AUTH_CHALLENGE_RESPONSE = (byte) 0x82;
  public static final byte CONST_TAG_AUTH_EXPONENTIATION = (byte) 0x85;

  //
  // PIV-specific ISO 7816 STATUS WORD (SW12) responses
  //
  public static final short SW_RETRIES_REMAINING = (short) 0x63C0;

  /*
   * PIV APPLICATION CONSTANTS
   */
  public static final short SW_REFERENCE_NOT_FOUND = (short) 0x6A88;
  public static final short SW_OPERATION_BLOCKED = (short) 0x6983;

  // The current authentication stage
  private static final short OFFSET_AUTH_STATE = (short) 0;

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
  // Command Chaining Handler
  private final ChainBuffer chainBuffer;
  // Cryptography Service Provider
  private final PIVSecurityProvider cspPIV;
  // A RAM working area to hold intermediate data and outgoing buffers
  private final byte[] scratch;
  // Holds any authentication related intermediary state
  private final byte[] authenticationContext;
  // Data Store
  private PIVDataObject firstDataObject;

  /**
   * Constructor
   *
   * @param chainBuffer A reference to the shared chainBuffer for multi-frame APDU support
   */
  public PIV(ChainBuffer chainBuffer) {

    //
    // Data Allocation
    //

    // Create our transient buffers
    scratch = JCSystem.makeTransientByteArray(LENGTH_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
    authenticationContext =
        JCSystem.makeTransientByteArray(LENGTH_AUTH_STATE, JCSystem.CLEAR_ON_DESELECT);

    // Create our chainBuffer reference and make sure its state is cleared
    this.chainBuffer = chainBuffer;
    chainBuffer.reset();

    // Create our PIV Security Provider
    cspPIV = new PIVSecurityProvider();

    // Create our TLV objects (we don't care about the result)
    TLVReader.getInstance();
    TLVWriter.getInstance();

    //
    // Pre-Personalisation
    //

    // Set the default PIN value (except for the Global PIN)
    if (Config.FEATURE_PIN_INIT_RANDOM) {
      cspPIV.generateRandom(scratch, (short) 0, Config.PIN_LENGTH_MAX);
      cspPIV.cardPIN.update(scratch, (short) 0, Config.PIN_LENGTH_MAX);
      PIVSecurityProvider.zeroise(scratch, (short) 0, Config.PIN_LENGTH_MAX);
    } else {
      cspPIV.cardPIN.update(Config.DEFAULT_PIN, (short) 0, (byte) Config.DEFAULT_PIN.length);
    }

    // Set the default PUK value
    if (Config.FEATURE_PUK_INIT_RANDOM) {
      // Generate a random value
      cspPIV.generateRandom(scratch, (short) 0, Config.PIN_LENGTH_MAX);
      cspPIV.cardPUK.update(scratch, (short) 0, Config.PIN_LENGTH_MAX);
      PIVSecurityProvider.zeroise(scratch, (short) 0, Config.PIN_LENGTH_MAX);
    } else {
      // Use the default from our configuration file
      cspPIV.cardPUK.update(Config.DEFAULT_PUK, (short) 0, (byte) Config.DEFAULT_PUK.length);
    }

    //
    // Test File System
    /*
     * TEST FILE SYSTEM
     * Use this to easily build the NIST-default filesystem
     *
    createDataObject((byte) 0x01, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x02, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x03, (byte) 0x01, (byte) 0x01);
    createDataObject((byte) 0x05, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x06, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x07, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x08, (byte) 0x01, (byte) 0x01);
    createDataObject((byte) 0x09, (byte) 0x01, (byte) 0x01);
    createDataObject((byte) 0x0A, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x0B, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x0C, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x0D, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x0E, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x0F, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x10, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x11, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x12, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x13, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x14, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x15, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x16, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x17, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x18, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x19, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1A, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1B, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1C, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1D, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1E, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x1F, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x20, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x21, (byte) 0x01, (byte) 0x01);
    createDataObject((byte) 0x61, (byte) 0x7F, (byte) 0x7F);
    createDataObject((byte) 0x7E, (byte) 0x7F, (byte) 0x7F);

    cspPIV.createKey((byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x83, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x84, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x85, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x86, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x87, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x88, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x89, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8A, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8B, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8C, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8D, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8E, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x8F, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x90, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x91, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x92, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x93, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x94, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x95, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x9A, (byte) 0x01, (byte) 0x00, (byte) 0x11, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9A, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9B, (byte) 0x7F, (byte) 0x00, (byte) 0x03, (byte) 0x01, (byte) 0x11);
    cspPIV.createKey((byte) 0x9B, (byte) 0x7F, (byte) 0x00, (byte) 0x08, (byte) 0x01, (byte) 0x11);
    cspPIV.createKey((byte) 0x9B, (byte) 0x7F, (byte) 0x00, (byte) 0x0A, (byte) 0x01, (byte) 0x11);
    cspPIV.createKey((byte) 0x9B, (byte) 0x7F, (byte) 0x00, (byte) 0x0C, (byte) 0x01, (byte) 0x11);
    cspPIV.createKey((byte) 0x9C, (byte) 0x02, (byte) 0x00, (byte) 0x11, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9C, (byte) 0x02, (byte) 0x00, (byte) 0x14, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9C, (byte) 0x02, (byte) 0x02, (byte) 0x07, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9D, (byte) 0x01, (byte) 0x00, (byte) 0x11, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x9D, (byte) 0x01, (byte) 0x00, (byte) 0x14, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x9D, (byte) 0x01, (byte) 0x01, (byte) 0x07, (byte) 0x02, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x03, (byte) 0x01, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x07, (byte) 0x04, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x08, (byte) 0x01, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x0A, (byte) 0x01, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x0C, (byte) 0x01, (byte) 0x10);
    cspPIV.createKey((byte) 0x9E, (byte) 0x7F, (byte) 0x7F, (byte) 0x11, (byte) 0x04, (byte) 0x10);
    */
  }

  /**
   * Called when this applet is selected, returning the APT object
   *
   * @param buffer The APDU buffer to write the APT to
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   * @return The length of the returned APT object
   */
  public short select(byte[] buffer, short offset) {

    //
    // PRE-CONDITIONS
    //

    // NONE

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Return the APT
    Util.arrayCopyNonAtomic(
        Config.DEFAULT_APT, (short) 0, buffer, offset, (short) Config.DEFAULT_APT.length);

    return (short) Config.DEFAULT_APT.length;
  }

  /**
   * Handles the PIV requirements for deselection of the application. Although this is not
   * explicitly stated as a PIV card command, its functionality is implied in the SELECT
   */
  public void deselect() {

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
    cspPIV.resetSecurityStatus();
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @return The length of the entire data object
   */
  public short getData(byte[] buffer, short offset) throws ISOException {

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

    PIVDataObject data = findDataObject(id);
    if (data == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return (short) 0; // Keep static analyser happy
    }

    // PRE-CONDITION 2 - The access rules must be satisfied for the requested object
    if (!cspPIV.checkAccessModeObject(data)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The requested object must be initialised with data
    if (!data.isInitialised()) {

      // 4.1.1 Data Object Content
      // Before the card is issued, data objects that are created but not used shall be set to
      // zero-length value.
      //
      // NOTE:
      // This description doesn't explicitly say whether the entire response should be zero
      // (i.e. SW12 only), or to return the data object tag with a zero length.
      //
      if (Config.FEATURE_ERROR_ON_EMPTY_DATA_OBJECT) {
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      } else {
        // We just return an OK response with no data
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
      }
      return (short) 0; // Keep static analyser happy
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Set up the outgoing chainbuffer
    short length = data.getLength();
    chainBuffer.setOutgoing(data.content, (short) 0, length, false);

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
  public void putData(byte[] buffer, short offset, short length) throws ISOException {

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

    // PRE-CONDITION 1 - The access rules must be satisfied for administrative access
    if (!cspPIV.checkAccessModeAdmin(false)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

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

        // PRE-CONDITION 2 - For all other objects, the 'DATA' tag must be present in the supplied
        // buffer
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
    PIVDataObject obj = findDataObject(id);
    if (obj == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return; // Keep static analyser happy
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Decide whether to clear or write/update
    short objectLength = TLVReader.getLength(buffer, offset);

    // If the data object length is zero, the caller is requesting that the object be cleared.
    if (objectLength == 0) {
      // STEP 2a - Clear the object
      obj.clear();
    } else {
      // STEP 2b - Calculate the total length of the object to allocate including TLV tag+length
      objectLength += (short) (TLVReader.getDataOffset(buffer, offset) - offset);

      // STEP 3 - Allocate the data object
      // NOTE: if the passed length is zero, this method will
      obj.allocate(objectLength);

      // STEP 4 - Recalculate the length of the first write, to account for the tag element being
      // removed
      length -= (short) (offset - initialOffset);

      // STEP 5 - Set up the incoming chainbuffer
      chainBuffer.setIncomingObject(obj.content, (short) 0, objectLength, false);

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
  public void verify(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    OwnerPIN pin = null;

    switch (id) {
      case ID_KEY_GLOBAL_PIN:
        // Make sure FEATURE_PIN_GLOBAL_ENABLED is set
        if (!Config.FEATURE_PIN_GLOBAL_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        pin = cspPIV.globalPIN;
        break;

      case ID_KEY_PIN:

        // Make sure FEATURE_PIN_CARD_ENABLED is set
        if (!Config.FEATURE_PIN_CARD_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        pin = cspPIV.cardPIN;
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // PRE-CONDITION 2 - If FEATURE_PIN_OVER_CONTACTLESS is not set, the interface must be contact
    if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
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
    if (!verifyPinFormat(id, buffer, offset, length)) {
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
    if ((pin.getTriesRemaining() <= Config.PIN_RETRIES_INTERMEDIATE) && cspPIV.getIsContactless()) {
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
  public void verifyGetStatus(byte id) throws ISOException {

    OwnerPIN pin = null;

    switch (id) {
      case ID_KEY_GLOBAL_PIN:

        // Make sure FEATURE_PIN_GLOBAL_ENABLED is set
        if (!Config.FEATURE_PIN_GLOBAL_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        pin = cspPIV.globalPIN;
        break;

      case ID_KEY_PIN:
        // Make sure FEATURE_PIN_CARD_ENABLED is set
        if (!Config.FEATURE_PIN_CARD_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        pin = cspPIV.cardPIN;
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
  public void verifyResetStatus(byte id) throws ISOException {

    // The security status of the key reference specified in P2 shall be set to FALSE and
    // the retry counter associated with the key reference shall remain unchanged.

    OwnerPIN pin = null;

    switch (id) {
      case ID_KEY_GLOBAL_PIN:

        // Make sure FEATURE_PIN_GLOBAL_ENABLED is set
        if (!Config.FEATURE_PIN_GLOBAL_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        pin = cspPIV.globalPIN;
        break;

      case ID_KEY_PIN:
        // Make sure FEATURE_PIN_CARD_ENABLED is set
        if (!Config.FEATURE_PIN_CARD_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        pin = cspPIV.cardPIN;
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
  public void changeReferenceData(byte id, byte[] buffer, short offset, short length)
      throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1
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

    OwnerPIN pin = null;
    byte intermediateLimit;

    switch (id) {
      case ID_KEY_GLOBAL_PIN:
        // Make sure FEATURE_PIN_GLOBAL_ENABLED is enabled (if you can't verify, you can't change
        // either)
        if (!Config.FEATURE_PIN_GLOBAL_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        // Make sure FEATURE_PIN_GLOBAL_CHANGE is enabled
        if (!Config.FEATURE_PIN_GLOBAL_CHANGE) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        // Check whether we are allowed to operate over contactless if applicable
        if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        pin = cspPIV.globalPIN;
        intermediateLimit = Config.PIN_RETRIES_INTERMEDIATE;
        break;

      case ID_KEY_PIN:
        // Make sure FEATURE_PIN_CARD_ENABLED is enabled (if you can't verify, you can't change
        // either)
        if (!Config.FEATURE_PIN_CARD_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        // Check whether we are allowed to operate over contactless if applicable
        if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        pin = cspPIV.cardPIN;
        intermediateLimit = Config.PIN_RETRIES_INTERMEDIATE;

        break;

      case ID_KEY_PUK:

        // Make sure FEATURE_PUK_CHANGE is enabled
        if (!Config.FEATURE_PUK_CHANGE) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

        // Check whether we are allowed to operate over contactless if applicable
        if (!Config.FEATURE_PUK_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        pin = cspPIV.cardPUK;
        intermediateLimit = Config.PUK_RETRIES_INTERMEDIATE;
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // If the current value of the retry counter associated with the key reference is zero, then the
    // reference data associated with the key reference shall not be changed and the
    // PIV Card Application shall return the status word '69 83'.
    if (pin.getTriesRemaining() == (short) 0) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // If the command is submitted over the contactless interface (VCI) and the current value of the
    // retry counter associated with the key reference is at or below the issuer-specified
    // intermediate retry value (see Section 3.2.1),
    // then the reference data associated with the key reference shall not be changed and the PIV
    // Card Application shall return the status word '69 83'.
    if (cspPIV.getIsContactless() && (pin.getTriesRemaining()) <= intermediateLimit)
      ISOException.throwIt(SW_OPERATION_BLOCKED);

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

    // Ensure the supplied length is exactly two PIN maximum lengths
    if (length != ((short) (Config.PIN_LENGTH_MAX + Config.PIN_LENGTH_MAX))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Verify the authentication reference data (old PIN) format
    if (!verifyPinFormat(id, buffer, offset, Config.PIN_LENGTH_MAX)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Verify the authentication reference data (old PIN) value
    if (!pin.check(buffer, offset, Config.PIN_LENGTH_MAX)) {
      // Return the number of retries remaining
      ISOException.throwIt((short) (SW_RETRIES_REMAINING | (short) pin.getTriesRemaining()));
    }

    // Move to the new reference data
    offset += Config.PIN_LENGTH_MAX;

    // Verify the new reference data (new PIN)
    if (!verifyPinFormat(id, buffer, offset, Config.PIN_LENGTH_MAX)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the security status of the key reference shall be set to
    // TRUE and the retry counter associated with the key reference shall be set to the reset retry
    // value associated with the key reference.

    // STEP 1 - Update the PIN
    pin.update(buffer, offset, Config.PIN_LENGTH_MAX);

    // STEP 2 - Verify the new PIN, which will have the effect of setting it to TRUE and resetting
    // the retry counter
    pin.check(buffer, offset, Config.PIN_LENGTH_MAX);

    // STEP 3 - Set the PIN ALWAYS flag as this is now verified
    cspPIV.setPINAlways(true);

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
  public void resetRetryCounter(byte id, byte[] buffer, short offset, short length)
      throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - Check if we are permitted to use this command over the contactless
    // interface.
    // NOTE: We must check this for both the PIN and the PUK
    if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (!Config.FEATURE_PUK_OVER_CONTACTLESS && cspPIV.getIsContactless()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The supplied ID must be the Card PIN
    // The only key reference allowed in the P2 parameter of the RESET RETRY COUNTER command is the
    // PIV Card Application PIN. If a key reference is specified in P2 that is not supported by the
    // card, the PIV Card Application shall return the status word '6A 88'.
    if (id != ID_KEY_PIN) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

    // PRE-CONDITION 3 - The supplied length must equal the PUK + NEW PIN lengths
    // If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall
    // not be reset and the PIV Card Application shall return the status word '69 83'.
    if (length != ((short) 2 * Config.PIN_LENGTH_MAX)) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // PRE-CONDITION 3 - The PUK must not be blocked
    // If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall
    // not be reset and the PIV Card Application shall return the status word '69 83'.
    if (cspPIV.cardPUK.getTriesRemaining() == (short) 0) ISOException.throwIt(SW_OPERATION_BLOCKED);

    // PRE-CONDITION 4 - Check the format of the NEW pin value
    // If the new reference data (PIN) in the command data field of the command does not satisfy the
    // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A
    // 80'.
    if (!verifyPinFormat(
        id, buffer, (short) (offset + Config.PIN_LENGTH_MAX), Config.PIN_LENGTH_MAX)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - Verify the PUK value
    // If the reset retry counter authentication data (PUK) in the command data field of the command
    // does not match reference data associated with the PUK, then the PIV Card Application shall
    // return the status word '63 CX'.
    if (!cspPIV.cardPUK.check(buffer, offset, Config.PIN_LENGTH_MAX)) {

      // Reset the PIN's security condition (see paragraph below for explanation)
      cspPIV.cardPIN.reset();

      // Check again if we are blocked
      if (cspPIV.cardPUK.getTriesRemaining() == (short) 0) {
        ISOException.throwIt(SW_OPERATION_BLOCKED);
      } else {
        // Return the number of retries remaining
        ISOException.throwIt(
            (short) (SW_RETRIES_REMAINING | (short) cspPIV.cardPUK.getTriesRemaining()));
      }
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
    cspPIV.cardPIN.update(buffer, (short) (offset + Config.PIN_LENGTH_MAX), Config.PIN_LENGTH_MAX);
  }

  /**
   * Allows the applet to provide security state information to PIV for access control
   *
   * @param isContactless Sets whether the current interface is contactless
   * @param isSecureChannel Sets whether the current command was issued over a GlobalPlatform Secure
   *     Channel
   */
  public void updateSecurityStatus(boolean isContactless, boolean isSecureChannel)
      throws ISOException {
    cspPIV.setIsContactless(isContactless);
    cspPIV.setIsSecureChannel(isSecureChannel);
  }

  /** Clears any intermediate authentication status used by 'GENERAL AUTHENTICATE' */
  private void authenticateReset() throws ISOException {
    PIVSecurityProvider.zeroise(authenticationContext, (short) 0, LENGTH_AUTH_STATE);
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
  public short generalAuthenticate(byte[] buffer, short offset, short length) throws ISOException {

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is more
    // of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short) 0);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return length;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer still contains the APDU header.

    // Set up our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, (short) 0, length);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key reference and mechanism must point to an existing key
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[ISO7816.OFFSET_P1]);

    if (key == null) {
      // If any key reference value is specified that is not supported by the card, the PIV Card
      // Application shall return the status word '6A 88'.
      cspPIV.setPINAlways(false); // Clear the PIN ALWAYS flag
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return (short) 0; // Keep compiler happy
    }

    // PRE-CONDITION 2 - The access rules must be satisfied for the requested key
    // NOTE: A call to this method automatically clears the PIN ALWAYS status.
    if (!cspPIV.checkAccessModeObject(key)) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return (short) 0; // Keep compiler happy
    }

    // PRE-CONDITION 3 - The key's private or secret values must have been set
    if (!key.isInitialised()) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return (short) 0; // Keep compiler happy
    }

    // PRE-CONDITION 4 - The Dynamic Authentication Template tag must be present in the data
    if (!reader.find(CONST_TAG_AUTH_TEMPLATE)) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }

    // Move into the content of the template
    reader.moveInto();

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Traverse the TLV to determine what combination of elements exist
    //
    short challengeOffset = (short) 0;
    short witnessOffset = (short) 0;
    short responseOffset = (short) 0;
    short exponentiationOffset = (short) 0;

    short challengeLength = (short) 0;
    short witnessLength = (short) 0;
    short responseLength = (short) 0;
    short exponentiationLength = (short) 0;

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
      // Variant A - Secure Messaging
      if (key.hasRole(PIVKeyObject.ROLE_SECURE_MESSAGING)) {
        if (key instanceof PIVKeyObjectECC) {
          return generalAuthenticateCase1A((PIVKeyObjectECC) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant B - Digital Signatures
      else if (key.hasRole(PIVKeyObject.ROLE_SIGN)) {
        if (key instanceof PIVKeyObjectPKI) {
          return generalAuthenticateCase1B((PIVKeyObjectPKI) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant C - RSA Key Transport
      else if (key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        if (key instanceof PIVKeyObjectRSA) {
          return generalAuthenticateCase1C((PIVKeyObjectRSA) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant D - Symmetric Internal Authentication
      else if (key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
        if (key instanceof PIVKeyObjectSYM) {
          return generalAuthenticateCase1D((PIVKeyObjectSYM) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Invalid case
      else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
        PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    // If any other tag combination is present in the first element of data, it is an invalid case.
    //
    else {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Done
    return (short) 0; // Keep compiler happy
  }

  // Variant A - Secure Messaging
  private short generalAuthenticateCase1A(
      PIVKeyObjectECC key, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state
    authenticateReset();

    // Reset they keys security status
    key.resetSecurityStatus();

    // TODO

    return (short) 0;
  }

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
    writer.init(scratch, (short) 0, challengeLength, CONST_TAG_AUTH_TEMPLATE);
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
      return (short) 0; // Keep static analyser happy
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
      return (short) 0; // Keep static analyser happy
    }

    // Now we can move past the signature data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
    writer.init(scratch, (short) 0, challengeLength, CONST_TAG_AUTH_TEMPLATE);
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
      return (short) 0; // Keep static analyser happy
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
      return (short) 0; // Keep static analyser happy
    }

    // Now we can move past the decrypted data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
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
    writer.init(scratch, (short) 0, challengeLength, CONST_TAG_AUTH_TEMPLATE);

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
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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

    // Reset they key's security status
    key.resetSecurityStatus();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the AUTHENTICATE role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT EXTERNAL attribute set
    if (key.hasAttribute(PIVKeyObject.ATTR_PERMIT_EXTERNAL)) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short length = key.getBlockLength();

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, (short) 0, length, CONST_TAG_AUTH_TEMPLATE);

    // Create the CHALLENGE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE);
    writer.writeLength(key.getBlockLength());

    // Generate the CHALLENGE data and write it to the output buffer
    short offset = writer.getOffset();
    cspPIV.generateRandom(scratch, offset, length);

    try {
      // Generate and store the encrypted CHALLENGE in our context, so we can compare it without
      // the key reference later.
      offset += key.encrypt(scratch, offset, length, authenticationContext, OFFSET_AUTH_CHALLENGE);
    } catch (Exception e) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      throw e;
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
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The RESPONSE tag length must be the same as our block length
    if (responseLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (Util.arrayCompare(
            scratch, responseOffset, authenticationContext, OFFSET_AUTH_CHALLENGE, responseLength)
        != 0) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // We are now authenticated. Set the key's security status
    key.setSecurityStatus();

    // Reset our authentication state
    authenticateReset();
    PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);

    // Done, no data to return
    return (short) 0;
  }

  private short generalAuthenticateCase4(PIVKeyObjectSYM key) throws ISOException {

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //

    // > Client application requests a WITNESS from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Reset they key security condition
    key.resetSecurityStatus();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // < PIV Card Application returns a WITNESS that is created by generating random
    //   data and encrypting it using the referenced key

    // Generate a block length worth of WITNESS data
    short length = key.getBlockLength();
    cspPIV.generateRandom(authenticationContext, OFFSET_AUTH_CHALLENGE, length);

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, (short) 0, length, CONST_TAG_AUTH_TEMPLATE);

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
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The WITNESS tag length must be the same as our block length
    if (witnessLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The CHALLENGE tag length must be equal to the witness length
    if (challengeLength != witnessLength) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (Util.arrayCompare(
            scratch, witnessOffset, authenticationContext, OFFSET_AUTH_CHALLENGE, witnessLength)
        != 0) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: The WITNESS is now verified, on to the CHALLENGE

    // > Client application requests encryption of CHALLENGE data from the card using the
    // > same key.

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, (short) 0, challengeLength, CONST_TAG_AUTH_TEMPLATE);

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
    key.setSecurityStatus();

    // Clear our authentication state
    authenticateReset();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
      PIVSecurityProvider.zeroise(scratch, (short) 0, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, (short) 0, length, CONST_TAG_AUTH_TEMPLATE);

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
    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

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
  public short generateAsymmetricKeyPair(byte[] buffer, short offset) throws ISOException {

    // Request Elements
    final byte CONST_TAG_TEMPLATE = (byte) 0xAC;
    final byte CONST_TAG_MECHANISM = (byte) 0x80;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The access rules must be satisfied for administrative access
    if (!cspPIV.checkAccessModeAdmin(false)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The 'TEMPLATE' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_TEMPLATE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Skip the length byte
    offset++;

    // PRE-CONDITION 3 - The 'MECHANISM' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The 'MECHANISM' tag must have a length of 1
    if (buffer[offset++] != (short) 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // NOTE: We ignore the existence of the 'PARAMETER' tag, because according to SP800-78-4 the
    // RSA public exponent is now fixed to 65537 (Section 3.1 PIV Cryptographic Keys).
    // ECC keys have no parameter.

    // PRE-CONDITION 5 - The key reference and mechanism must point to an existing key
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[offset]);
    if (key == null) {
      // NOTE: The error message we return here is different dependant on whether the key is bad
      // (6A86), or the mechanism is bad (6A80) (See SP800-73-4 3.3.2 Generate Asymmetric Key pair).
      if (!cspPIV.keyExists(buffer[ISO7816.OFFSET_P2])) {
        // The key reference is bad
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      } else {
        // The mechanism is bad
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    // PRE-CONDITION 6 - The key must be an asymmetric key (key pair)
    if (!(key instanceof PIVKeyObjectPKI)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return (short) 0; // Keep static analyser happy
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Generate the key pair
    PIVKeyObjectPKI keyPair = (PIVKeyObjectPKI) key;
    short length = keyPair.generate(scratch, (short) 0);

    chainBuffer.setOutgoing(scratch, (short) 0, length, true);

    // Done, return the length of the object we are writing back
    return length;
  }

  /**
   * Performs data validation on an incoming PIN number to ensure that it conforms to SP800-73-4
   * Part 2 - Authentication of an Individual
   *
   * @param id The requested PIN reference to verify
   * @param buffer The buffer containing the PIN
   * @param offset The offset of the PIN data
   * @param length The length of the PIN data
   * @return True if the supplied PIN conforms to the format requirements
   */
  private boolean verifyPinFormat(byte id, byte[] buffer, short offset, short length)
      throws ISOException {

    final byte CONST_PAD = (byte) 0xFF;

    // The pairing code shall be exactly 8 bytes in length and the PIV Card Application
    // PIN shall be between 6 and 8 bytes in length. If the actual length of PIV Card Application
    // PIN is less than 8 bytes it shall be padded to 8 bytes with 'FF' when presented to the card
    // command interface. The 'FF' padding bytes shall be appended to the actual value of the PIN.

    // NOTE: We define the minimum and maximum lengths in configuration, but only the max is checked
    //		 here because of the padding requirement
    if (length != Config.PIN_LENGTH_MAX) return false;

    // The PUK shall be 8 bytes in length, and may be any 8-byte binary value. That is, the bytes
    // comprising the PUK may have any value in the range 0x00-0xFF.
    // NOTE: This means there is no further validation to perform for the PUK
    if (id == ID_KEY_PUK) return true;

    // The bytes comprising the PIV Card Application PIN and pairing code shall be limited to values
    // 0x30-0x39, the ASCII values for the decimal digits '0'-'9'. For example,
    // 		+ Actual PIV Card Application PIN: '123456' or '31 32 33 34 35 36'
    //		+ Padded PIV Card Application PIN presented to the card command interface: '31 32 33 34 35
    // 36 FF FF'

    // The PIV Card Application shall enforce the minimum length requirement of six bytes for the
    // PIV Card Application PIN (i.e., shall verify that at least the first six bytes of the value
    // presented to the card command interface are in the range 0x30-0x39) as well as the other
    // formatting requirements specified in this section.

    // If the Global PIN is used by the PIV Card Application, then the above encoding, length,
    // padding, and enforcement of minimum PIN length requirements for the PIV Card Application
    // PIN shall apply to the Global PIN.
    boolean padding = false;
    for (short i = 0; i < Config.PIN_LENGTH_MAX; i++) {

      if (padding) {
        // Once we have reached padding, all subsequent characters must be padding
        if (buffer[offset] != CONST_PAD) return false;
      } else {
        // Check if we have reached our padding
        if (buffer[offset] == CONST_PAD) {
          if (i < Config.PIN_LENGTH_MIN) {
            // RULE: The minimum PIN length has not been reached
            return false;
          } else {
            padding = true;
          }
        } else if (buffer[offset] < '0' || buffer[offset] > '9') {
          // RULE: The PIN character is not between '0' and '9' (inclusive)
          return false;
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

  /**
   * This is the administrative equivalent for the PUT DATA card and is intended for use by Card
   * Management Systems to generate the on-card file-system.
   *
   * @param buffer - The incoming APDU buffer
   * @param offset - The starting offset of the CDATA section
   * @param length - The length of the CDATA section
   */
  public void putDataAdmin(byte[] buffer, short offset, short length) throws ISOException {

    final byte CONST_TAG_COMMAND = (byte) 0x30;
    final byte CONST_TAG_OPERATION = (byte) 0x8A;
    final byte CONST_TAG_ID = (byte) 0x8B;
    final byte CONST_TAG_MODE_CONTACT = (byte) 0x8C;
    final byte CONST_TAG_MODE_CONTACTLESS = (byte) 0x8D;
    final byte CONST_TAG_KEY_MECHANISM = (byte) 0x8E;
    final byte CONST_TAG_KEY_ROLE = (byte) 0x8F;
    final byte CONST_TAG_KEY_ATTRIBUTE = (byte) 0x90;

    final byte CONST_OP_DATA = (byte) 0x01;
    final byte CONST_OP_KEY = (byte) 0x02;

    //
    // SECURITY PRE-CONDITION
    //

    // The command must have been sent over SCP with CEnc+CMac
    if (!cspPIV.checkAccessModeAdmin(true)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short) 0);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming command. Keep in mind that
    // the original buffer still contains the APDU header.

    // Initialise our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, (short) 0, length);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'COMMAND' constructed tag must be present
    if (!reader.match(CONST_TAG_COMMAND)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 2 - The SEQUENCE length must be smaller than the APDU data length
    if (reader.getLength() > length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Move into the constructed tag
    reader.moveInto();

    // PRE-CONDITION 3 - The mandatory 'OPERATION' tag must be present with length 1
    if (!reader.match(CONST_TAG_OPERATION)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte operation = reader.toByte();

    // PRE-CONDITION 4 - The 'OPERATION' value must be set to the value CONST_OP_DATA or
    // CONST_OP_KEY
    if (operation != CONST_OP_DATA && operation != CONST_OP_KEY)
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);

    // Move to the next tag
    reader.moveNext();

    // PRE-CONDITION 5 - The 'ID' value must be present
    if (!reader.match(CONST_TAG_ID)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

    byte id;
    if (CONST_OP_KEY == operation) {
      // PRE-CONDITION 6a - For keys, the 'ID' length must be 1
      if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      id = reader.toByte();
    } else if (CONST_OP_DATA == operation) {
      //
      // IMPLEMENTATION NOTE:
      // We are progressing through to supporting multi-byte definition of data objects, so until
      // this is fully completed, we will accept 1-3 byte length identifiers and just use the final
      // byte as the identifier. This means if you pass through '5FC101' and '6FC101' it will fail
      // until we support the 3-bytes internally.
      //

      // PRE-CONDITION 6b - The data objects, the 'ID' length must be between 1 and 3
      if (reader.getLength() > (short) 3) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

      // Use the last byte of the value as the identifier
      offset = reader.getDataOffset();
      offset += reader.getLength();
      offset--;
      id = scratch[offset];
    } else {
      // Invalid operation identifier
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep compiler happy
    }

    // Move to the next tag
    reader.moveNext();

    // PRE-CONDITION 6 - The 'MODE CONTACT' value must be present with length 1
    if (!reader.match(CONST_TAG_MODE_CONTACT)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    byte modeContact = reader.toByte();

    // Move to the next tag
    reader.moveNext();

    // PRE-CONDITION 7 - The 'MODE CONTACTLESS' value must be present with length 1
    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    byte modeContactless = reader.toByte();

    byte keyMechanism = ID_ALG_DEFAULT;
    byte keyRole = PIVKeyObject.ROLE_NONE;
    byte keyAttribute = PIVKeyObject.ATTR_NONE;

    // Move to the next tag
    reader.moveNext();

    if (CONST_OP_KEY == operation) {

      // PRE-CONDITION 8a - If the operation is CONST_OP_KEY, then the 'KEY MECHANISM' tag
      //					 must be present with length 1
      if (!reader.match(CONST_TAG_KEY_MECHANISM)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      keyMechanism = reader.toByte();

      // Move to the next tag
      reader.moveNext();

      // PRE-CONDITION 8b - If the operation is CONST_OP_KEY, then the 'KEY ROLE' tag
      //					 must be present with length 1

      if (!reader.match(CONST_TAG_KEY_ROLE)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      keyRole = reader.toByte();

      // Move to the next tag
      reader.moveNext();

      // PRE-CONDITION 8c - If the operation is CONST_OP_KEY, then the 'KEY ATTRIBUTE' tag
      //					 may be present with length 1
      if (!reader.match(CONST_TAG_KEY_ATTRIBUTE)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      if (reader.getLength() != (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      keyAttribute = reader.toByte();

      // PRE-CONDITION 8c - If 'OPERATION' is set to CONST_OP_KEY, the key referenced by the 'id'
      //					  and 'mechanism' values must not already exist in the key store
      if (cspPIV.selectKey(id, keyMechanism) != null) {
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }

    } else { // (CONST_OP_DATA == operation)

      // PRE-CONDITION 8d - If 'OPERATION' is set to CONST_OP_DATA, the object referenced by 'id'
      // value
      // 					 must not already exist in the data store
      PIVObject obj = firstDataObject;
      while (obj != null) {
        if (obj.getId() == id) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        obj = obj.nextObject;
      }
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - If the operation is a DATA OBJECT, add it to the data store
    if (operation == CONST_OP_DATA) {
      createDataObject(id, modeContact, modeContactless);
    } else { // (operation == CONST_OP_KEY)
      cspPIV.createKey(id, modeContact, modeContactless, keyMechanism, keyRole, keyAttribute);
    }
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
  public void changeReferenceDataAdmin(byte id, byte[] buffer, short offset, short length)
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
    if (!cspPIV.checkAccessModeAdmin(true)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short) 0);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer
    // still contains the APDU header.

    //
    // PIN cases
    //

    if (id == ID_KEY_PIN) {
      if (!verifyPinFormat(ID_KEY_PIN, scratch, (short) 0, length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      // Update the PIN
      cspPIV.cardPIN.update(scratch, (short) 0, (byte) length);

      // Done
      return;
    } else if (id == ID_KEY_PUK) {
      if (!verifyPinFormat(ID_KEY_PUK, scratch, (short) 0, length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      // Update the PUK
      cspPIV.cardPUK.update(scratch, (short) 0, (byte) length);

      // Done
      return;
    } else {
      // Key component: Input format validation required is handled by the key
    }

    // PRE-CONDITION 1 - The key reference and mechanism MUST point to an existing key
    PIVKeyObject key = cspPIV.selectKey(id, buffer[ISO7816.OFFSET_P1]);
    if (key == null) {
      // If any key reference value is specified that is not supported by the card, the PIV Card
      // Application
      // shall return the status word '6A 88'.
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
    reader.init(scratch, (short) 0, length);

    // PRE-CONDITION 2 - The parent tag MUST be of type SEQUENCE
    if (!reader.match(CONST_TAG_SEQUENCE)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 3 - The SEQUENCE length MUST be smaller than the APDU data length
    if (reader.getLength() > length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // Move to the child tag
    reader.moveInto();

    //
    // EXECUTION STEPS
    //

    key.updateElement(reader.getTag(), scratch, reader.getDataOffset(), reader.getLength());
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @return The length of the entire data object
   */
  public short getDataExtended(byte[] buffer, short offset, short length) throws ISOException {

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
    Util.arrayCopyNonAtomic(buffer, offset, scratch, (short) 0, length);
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, (short) 0, length);

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

    // Prepare the writer to start at offset 2 to allow for the CONST_TAG_DATA tag and length
    // NOTE: We write it later when we know what the actual length is
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, (short) 2, TLV.LENGTH_1BYTE_MAX, TLV.ASN1_SEQUENCE);

    switch (id) {
      case CONST_DO_GET_VERSION:
        /*
         # The ASN.1 format of this response is:
         GetVersionResponse ::= SEQUENCE
         {
           major    INTEGER,
           minor    INTEGER,
           revision INTEGER,
           debug    BOOLEAN
         }

         # So, the following data:
         value GetVersionResponse ::= {
           major 1,
           minor 2,
           revision 3,
           debug FALSE
         }

         # Would be encoded using DER-TLV as:
         300C8001 01810102 82010383 0100
        */
        writer.write(TLV.ASN1_INTEGER, Config.VERSION_MAJOR);
        writer.write(TLV.ASN1_INTEGER, Config.VERSION_MINOR);
        writer.write(TLV.ASN1_INTEGER, Config.VERSION_REVISION);
        writer.write(TLV.ASN1_BOOLEAN, Config.VERSION_DEBUG);
        length = writer.finish();
        break;

      case CONST_DO_GET_STATUS:
        /*
           # The ASN.1 format of this response is:
        AppletState ::= ENUMERATED {
          installed (3),
             selectable (1),
          secured (15),
          terminated (127)
         }
        GetStatusResponse ::= SEQUENCE
           {
             appletState   AppletState
           }

           # So, the following data:
           value GetStatusResponse ::= {
             appletState secured
           }

           # Would be encoded using DER-TLV as:
           300380010F
          */

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

        // Calculate the number of keys initialised
        writer.write(TLV.ASN1_ENUMERATED, GPSystem.getCardContentState());
        length = writer.finish();
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // Length sanity check (I should never construct a length larger than a short length)
    if (length > TLV.LENGTH_1BYTE_MAX) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Reset to the start of the buffer to write the response tag
    offset = (short) 0;
    scratch[offset++] = CONST_TAG_DATA;
    length++;
    scratch[offset] = (byte) length;
    length++;

    // STEP 1 - Set up the outgoing chainbuffer
    chainBuffer.setOutgoing(scratch, (short) 0, length, false);

    // Done - return how many bytes we will process
    return length;
  }

  /**
   * Searches for a data object within the local data store
   *
   * @param id The data object to find
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

  /**
   * Adds a data object to the data store
   *
   * @param id of the data object to create (just the LSB)
   * @param modeContact Access Mode control flags
   * @param modeContactless Access Mode control flags
   */
  private void createDataObject(byte id, byte modeContact, byte modeContactless) {

    // Create our new key
    PIVDataObject dataObject = new PIVDataObject(id, modeContact, modeContactless);

    // Add it to our linked list
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

    //
    // SPECIAL OBJECT - Discovery Data
    // This automatically populates the discovery object if it is added, based on our compiled
    // configuration
    //
    if (Config.FEATURE_DISCOVERY_OBJECT_DEFAULT && ID_DATA_DISCOVERY == id) {

      dataObject.allocate((short) Config.DEFAULT_DISCOVERY.length);

      Util.arrayCopyNonAtomic(
          Config.DEFAULT_DISCOVERY,
          (short) 0,
          dataObject.content,
          (short) 0,
          (short) Config.DEFAULT_DISCOVERY.length);
    }
  }
}
