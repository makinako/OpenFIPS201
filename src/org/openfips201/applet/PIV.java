/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201 Copyright: (c) 2025 Commonwealth of Australia 
 * Author: Kim O'Sullivan / Makina (kim@makina.com.au / @makinako)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

package org.openfips201.applet;

import org.globalplatform.GPSystem;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

/**
 * Implements the FIPS201-2 card application, according to NIST SP800-73-4.
 *
 * <p>
 * It implements the following functionality: - Compiles to Java Card 2.2.2 for maximum
 * compatibility - A flexible file system that can be defined easily without recompiling - A
 * flexible key store that defines key roles instead of hard-coding which key is used for what
 * function - Secure personalisation over SCP w/CEnc+CMac using the CHANGE REFERENCE DATA and PUT
 * DATA commands
 * </p>
 *
 * <p>
 * The following is out-of-scope in this revision: - Virtual contact interface - Secure messaging
 * using Opacity - Biometric on-card comparison (OCC)
 * </p>
 */
final class PIV {

  //
  // Constants - General Authenticate
  // NOTE: These constants are related to the 'GENERAL AUTHENTICATE' command, not
  // necessarily applet authentication.
  //

  // The current authentication stage
  private static final short OFFSET_GA_STATE = (short) 0;

  // The key id used in the current authentication
  private static final short OFFSET_GA_ID = (short) 1;

  // The key mechanism used in the current authentication
  private static final short OFFSET_GA_MECHANISM = (short) 2;

  // The GENERAL AUTHENTICATE challenge buffer
  private static final short OFFSET_GA_CHALLENGE = (short) 3;

  // The length to allocate for holding CHALLENGE or WITNESS data for general
  // authenticate. It needs to support a 16-byte nonce for AES authentication
  private static final short LENGTH_GA_CHALLENGE = (short) 16;

  private static final short LENGTH_GA_STATE = (short) (4 + LENGTH_GA_CHALLENGE);

  // A CHALLENGE has been requested by the client application (Basic
  // Authentication)
  private static final short GA_STATE_EXTERNAL = (short) 1;

  // A WITNESS has been requested by the client application (Mutual
  // Authentication)
  private static final short GA_STATE_MUTUAL = (short) 2;

  //
  // Persistent Objects
  //

  // PERSISTENT - Configuration Store
  private final Config config;

  // PERSISTENT - Data Store
  private final PIVDataStore dataStore;

  // PERSISTENT - PIV Secure Messaging
  private final ChannelPIVSM channelPIVSM;

  // TRANSIENT - Holds intermediary state related to the GENERAL AUTHENTICATE command
  private final byte[] generalAuthState;

  // PERSISTENT - Holds the operator authentication state
  private final Operator operator;

  PIV() {
    // Our general authentication state only exists to facilitate temporary authentication data
    // so we don't need to persist across selection.
    generalAuthState = JCSystem.makeTransientByteArray(LENGTH_GA_STATE, JCSystem.CLEAR_ON_DESELECT);

    operator = new Operator();

    // Create our persistent objects
    config = new Config();
    dataStore = new PIVDataStore();
    channelPIVSM = new ChannelPIVSM();

    // Pre-allocate our singleton TLV objects
    TLVReader.allocate();
    TLVWriter.allocate();
  }

  ChannelPIVSM getSecureMessaging() {
    return channelPIVSM;
  }

  void setRoleAdmin() {
    operator.performIntegrityCheck();
    operator.setRole(Operator.ROLE_ADMIN);
  }

  /**
   * Called when this applet is selected, returning the APT object
   *
   * @param buffer The APDU buffer to write the APT to
   * @param offset The starting offset of the CDATA section
   */
  void select(PIVAPDU pApdu) {

    //
    // PRE-CONDITIONS
    //

    // NONE

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Return the APT (NOTE: We know that this will fit in a single-byte field.)
    byte[] buffer = pApdu.getData();
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, TLV.LENGTH_1BYTE_MAX, Config.APT_TAG);

    // AID
    writer.write(Config.APT_AID_TAG, Config.APT_AID_DATA, Constants.ZERO_SHORT, (short) Config.APT_AID_DATA.length);

    // CTAA
    writer.write(Config.APT_CTAA_TAG, Config.APT_CTAA_DATA, Constants.ZERO_SHORT, (short) Config.APT_CTAA_DATA.length);

    // Application Label
    writer.write(Config.APT_LABEL_TAG, Config.APT_LABEL_DATA, Constants.ZERO_SHORT,
        (short) Config.APT_LABEL_DATA.length);

    // URL
    writer.write(Config.APT_URL_TAG, Config.APT_URL_DATA, Constants.ZERO_SHORT, (short) (Config.APT_URL_DATA.length));

    // AC (Only with PIVSM)
    if (channelPIVSM.isInitialised()) {
      if (channelPIVSM.getSupportedMechanism() == Constants.ID_ALG_ECC_CS2) {
        // CS2
        writer.write(Config.APT_AC_TAG, Config.APT_AC_DATA_CS2, Constants.ZERO_SHORT,
            (short) (Config.APT_AC_DATA_CS2.length));
      } else {
        // CS7
        writer.write(Config.APT_AC_TAG, Config.APT_AC_DATA_CS7, Constants.ZERO_SHORT,
            (short) (Config.APT_AC_DATA_CS7.length));
      }
    }

    short length = writer.finish();
    pApdu.setOutgoingAPDU(Constants.ZERO_SHORT, length);
  }

  void deselect(boolean reselecting) {
    if (reselecting) {
      // Check operator integrity
      operator.performIntegrityCheck();

      // Only clear the ADMIN state
      operator.clearRole(Operator.ROLE_ADMIN);
    } else {
      // Clear all operator states and verifiers
      operator.reset();
      dataStore.resetVerifiers();
    }
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   */
  void getData(PIVAPDU pApdu) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final byte CONST_DATA = (byte) 0x53;

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The length must be between 3 and 5 bytes
    // NOTE: Format is [5C] [L:1] [T:1-3]
    if (length < 3 || length > 5) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 2 - The 'TAG' data element must be present
    // NOTE: This is parsed manually rather than going through a TLV parser
    if (buffer[offset++] != CONST_TAG) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Check SW12
    }

    byte tagLength = buffer[offset++];

    // Retrieve the data object TAG identifier
    // PRE-CONDITION 3 - The 'TAG' length must be between 1 and 3
    // This is checked in parseId
    int id = PIVContainer.parseId(buffer, offset, tagLength);

    // Retrieve the corresponding object
    PIVContainer object = dataStore.getContainer(id);

    // PRE-CONDITION 1 - The specified tag must exist in the data store
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 3 - The access rules must be satisfied for the requested object
    checkAccessPrivilege(object, pApdu);

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - The requested object must be initialised with data
    // From SP800-73-5 4.1.1 Data Object Content:
    // Before the card is issued, data objects that are created but not used shall be set to zero-length value.
    //
    if (!object.isInitialised()) {

      switch (id) {
      // SPECIAL - Handle the dynamic discovery object case
      case Constants.ID_DATA_DISCOVERY:
        length = buildDiscoveryObject(buffer, Constants.ZERO_SHORT);
        break;

      // Special - Handle the 2-byte BITG case
      case Constants.ID_DATA_BITG:
        buffer[0] = Constants.ID_DATA_BITG_MSB;
        buffer[1] = Constants.ID_DATA_BITG_MSB;
        buffer[2] = 0;
        length = 3;
        break;

      default:
        buffer[0] = CONST_DATA;
        buffer[1] = 0;
        length = 2;
        break;
      }

      pApdu.setOutgoingAPDU(Constants.ZERO_SHORT, length);
    } else {
      // All initialised objects
      pApdu.setOutgoingObject(object.getContent(), Constants.ZERO_SHORT, object.getLength());
    }
  }

  /**
   * The PUT DATA card command completely replaces the data content of a single data object in the
   * PIV Card Application with new content.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   * @return The offset to start processing from in the content buffer
   */
  short putData(PIVAPDU pApdu) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final byte CONST_DATA = (byte) 0x53;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The tag must be one of the correctly formatted tag
    // identifiers
    // NOTE: We don't support the OpenFIPS201 extended tag 2F here.
   
    //
    // Retrieve the data object TAG identifier
    // NOTE: All objects in the data store have had their tag reduced to one byte,
    // which is
    // always the least significant byte of the tag.
    //
    int id = 0;

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();

    switch (buffer[offset]) {

    //
    // SPECIAL OBJECT - Discovery Object
    //
    case Constants.ID_DATA_DISCOVERY:
      id = Constants.ID_DATA_DISCOVERY;
      break;

    //
    // SPECIAL OBJECT - Biometric Information Template Group
    //
    case Constants.ID_DATA_BITG_MSB:
      offset++;
      if (buffer[offset] != Constants.ID_DATA_BITG_LSB) {
        ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
      }
      id = Constants.ID_DATA_BITG; // Store it as our object ID
      break;

    //
    // All other objects
    //
    case CONST_TAG:
      offset++; // Move to the length byte
      short tagLength = buffer[offset++];
      id = PIVContainer.parseId(buffer, offset, tagLength);

      // PRE-CONDITION 2 - For other objects, the 'DATA' tag must be present in the
      // buffer
      offset += tagLength; // Skip past the tag
      if (buffer[offset] != CONST_DATA) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      break;

    default:
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // The offset now holds the correct position for writing the object, including
    // the DATA tag

    // PRE-CONDITION 2 - The tag supplied in the 'TAG LIST' element must exist in
    // the data store
    PIVContainer container = dataStore.getContainer(id);
    if (container == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return Constants.ZERO_SHORT;
    }

    // PRE-CONDITION 3 - The access rules must be satisfied for write access must be
    // satisfied. Either:
    // a) with an administrative command; or
    // b) the currently authenticated key has explicit permission to write to this object.
    //
    try {
      checkWritePrivilege(container, pApdu);      
    } catch (ISOException ex) {
      // NOTE:
      // When using the Virtual Contact Interface, the error status changes for a failure here.
      if (ex.getReason() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED && isVirtualContactInterface(pApdu)) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      } else {
        throw ex;
      }
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Write the new object
    short objectLength = TLVReader.getLength(buffer, offset);
    if (objectLength > Constants.ZERO_SHORT) {

      // STEP 2 - Calculate the total length of the object to allocate including TLV header
      objectLength += (short) (TLVReader.getDataOffset(buffer, offset) - offset);

      // STEP 3 - Set up the incoming object buffer
      pApdu.setIncomingObject(container, objectLength, false);

      // Done - Return the offset to start writing from in the content buffer
      return offset;
    } else {
      container.clear();
      pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
      return Constants.ZERO_SHORT;
    }
  }

  // The verify method should authenticate the operator
  static final byte VERIFY_MODE_AUTH = (byte) 1;

  // The verify method should reset the operator verification
  static final byte VERIFY_MODE_RESET = (byte) 2;

  // The verify method should get the current verification status
  static final byte VERIFY_MODE_GET_STATUS = (byte) 3;

  /**
   * The VERIFY card command initiates the comparison in the card of the reference data indicated by
   * the key reference with authentication data in the data field of the command.
   *
   * @param mode   The operation mode for PIN_VERIFICATION
   * @param id     The requested PIN reference
   * @param pApdu  The incoming APDU object
   * @param length The length of the verification value
   */
  @SuppressWarnings("fallthrough")   
  void verify(byte mode, byte id, PIVAPDU pApdu, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // Check operator integrity
    operator.performIntegrityCheck();

    // PRE-CONDITION 1: The requested verifier must be defined
    PIVVerifier verifier = dataStore.getVerifier(id);
    if (verifier == null) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 2: If PUK and VCI COMPATIBILITY MODE is disabled, it cannot be used over VCI
    // NOTE: Under no circumstances does the PIV standard PUK usage auth over contactless
    if (id == Constants.ID_AUTH_PUK && !config.readFlag(Config.CONFIG_VCI_COMPATIBILITY_MODE)
        && Platform.isContactless() && isVirtualContactInterface(pApdu)) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION 2: The verifier must be permitted
    checkAccessPrivilege(verifier, pApdu);

    //
    // EXECUTION STEPS
    //

    switch (mode) {

    case VERIFY_MODE_AUTH:
    case VERIFY_MODE_RESET:
      // Reset the target verifier
      verifier.reset();

      switch (id) {
      case Constants.ID_AUTH_LOCAL_PIN:
      case Constants.ID_AUTH_GLOBAL_PIN:
        // Reset the role only if no other USER role verifiers are validated
        if (!dataStore.isUserVerified()) {
          operator.clearRole(Operator.ROLE_USER);
        }
        break;

      case Constants.ID_AUTH_PUK:
        operator.clearRole(Operator.ROLE_SECURITY_OFFICER);
        break;

      default:
        break;
      }

      // If we are only resetting, there is nothing else to do.
      if (mode == VERIFY_MODE_RESET) {
        break;
      }

      // In order to protect against blocking over the contactless interface, PIV Card
      // Applications that implement secure messaging shall define an issuer-specified
      // intermediate retry value for each of these key references and return '69 83'
      // if the command is submitted over the contactless interface (over secure
      // messaging or the VCI, as required for the key reference) and the current
      // value of the retry counter associated with the key reference is at or below
      // the issuer-specified intermediate retry value. If status word '69 83' is
      // returned, then the comparisonshall not be made, and the security status and
      // the retry counter of the key reference shall remain unchanged.

      // PRE-CONDITION 4 - If using the contactless interface, the pin retries
      // remaining must not fall below the specified intermediate retry amount.
      // NOTES:
      // - Regular PIN blocking is reported later, since the PIN object will not
      // permit a check if the # of retries are zero.
      if (Platform.isContactless() && verifier.getContactlessTriesRemaining() <= Constants.ZERO_BYTE) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }

      // PRE-CONDITION 4 - The supplied PIN format must be valid
      // - If the key reference is '00' or '80' and the authentication data in the
      // command data field does not satisfy the criteria in Section 2.4.3, then the
      // card command shall fail and the PIV Card Application shall return either the
      // status word '6A 80' or '63 CX'.
      // - If status word '6A 80' is returned, the security status and the retry
      // counter of the key reference shall remain unchanged. If status word '63 CX'
      // is returned, the security status of the key reference shall be set to FALSE
      // and the retry counter associated with the key reference shall be decremented
      // by one.
      //
      // NOTE:
      // - We return 6A80 (WRONG DATA) and therefore do NOT decrement the counter or block
      byte[] buffer = pApdu.getData();
      short offset = pApdu.getDataOffset();

      // Verify the PIN (we verify the maximum length, not the supplied length)
      if (verifier.check(buffer, offset, length)) {

        // We are verified, set the active role state based on the ID
        switch (id) {
        case Constants.ID_AUTH_LOCAL_PIN:
        case Constants.ID_AUTH_GLOBAL_PIN:
        case Constants.ID_AUTH_OCC_PRI:
        case Constants.ID_AUTH_OCC_SEC:
          operator.setRole(Operator.ROLE_USER);
          break;

        case Constants.ID_AUTH_PUK:
          operator.setRole(Operator.ROLE_SECURITY_OFFICER);
          break;

        case Constants.ID_AUTH_PAIRING_CODE:
          // This is not an authentication method, just a terminal binding. It does not assume
          // a role and is just used to permit the VCI condition if present.
          break;

        default:
          // This is an insane state and indicates a bug somewhere
          ISOException.throwIt(ISO7816.SW_UNKNOWN);
          break;
        }

        // We are done
        break;
      }

      // NOTE: We deliberately fall through to the next case here since we have
      // not verified successfully, so we must return the correct status.      
      // fall through
      
    case VERIFY_MODE_GET_STATUS:
      // Return the correct retry counter
      short remaining;
      if (Platform.isContactless()) {
        remaining = verifier.getContactlessTriesRemaining();
      } else {
        remaining = verifier.getContactTriesRemaining();
      }

      // Check for a blocked PIN
      if (remaining <= (byte) 0) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }

      // If we are not blocked, but not validated
      if (!verifier.isValidated()) {
        // Return the number of retries remaining, with the special case for unlimited retries
        // Which is mandated by the Pairing Code.
        if (verifier.getTryLimit() == 0) {
          remaining = 0;
        }
        ISOException.throwIt((short) (Constants.SW_RETRIES_REMAINING | remaining));
      }

      // If we got this far, we are validated and can just return SW_OK by default
      break;

    default:
      // This is an insane state and indicates a bug somewhere
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
      break;
    }

    // Indicate we have no response data
    pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
  }

  /**
   * The CHANGE REFERENCE DATA card command initiates the comparison of the authentication data in
   * the command data field with the current value of the reference data and, if this comparison is
   * successful, replaces the reference data with new reference data.
   *
   * @param id     The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void changeReferenceData(byte id, PIVAPDU pApdu) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // Only reference data associated with key references '80' and '81' specific to
    // the PIV Card Application (i.e., local key reference) and the Global PIN with
    // key reference '00' may be changed by the PIV Card Application CHANGE REFERENCE
    // DATA command.
    //
    // Key reference '80' reference data shall be changed by the PIV Card Application
    // CHANGE REFERENCE DATA command.
    //
    // The ability to change reference data associated with key references '81' and
    // '00' using the PIV Card Application CHANGE REFERENCE DATA command is
    // optional.
    //
    // TRANSLATION:
    // - The local PIN must be changeable with this command (though it says may?)
    // - The global PIN and PUK may optionally be changed with this command
    //
    // If key reference '81' is specified and the command is submitted over the
    // contactless interface (including SM or VCI), then the card command shall
    // fail.
    //
    // If key reference '00' or '80' is specified and the command is not submitted
    // over either the contact interface or the VCI, then the card command shall
    // fail.
    //
    // In each case, the security status and the retry counter of the key reference
    // shall remain unchanged.
    //
    // TRANSLATION:
    // - The global PIN can't be changed over contactless under any circumstances
    // - The local PIN can be changed over contactless with VCI only.
    // - The PUK cannot be changed over contactless at all, even with VCI.
    //
    // If the current value of the retry counter associated with the key reference
    // is zero, then the reference data associated with the key reference shall not
    // be changed and the PIV Card Application shall return the status word '69 83'.
    //
    // TRANSLATION:
    // - A blocked PIN/PUK cannot be changed with this command.
    //
    // IMPLEMENTATION NOTES:
    // - This logic is defined in the verify() method

    // If the command is submitted over the contactless interface (VCI) and the
    // current value of the retry counter associated with the key reference is at or
    // below the issuer-specified intermediate retry value (see Section 3.2.1),
    // then the reference data associated with the key reference shall not be
    // changed and the PIV Card Application shall return the status word '69 83'.
    //
    // TRANSLATION:
    // - If changed over the contactless interface (with VCI), you use the
    // intermediate value to decide whether the PIN/PUK is blocked.
    //
    // IMPLEMENTATION NOTES:
    // - This logic is defined in the verify() method

    // If the authentication data in the command data field does not match the
    // current value of the reference data or if either the authentication data
    // or the new reference data in the command data field of the command does not
    // satisfy the criteria in Section 2.4.3, the PIV Card Application shall not
    // change the reference data associated with the key reference and shall return
    // either status word '6A 80' or '63 CX', with the following restrictions.
    //
    // TRANSLATION:
    // - If the old PIN/PUK is wrong, this command must fail
    // - If the format of the old or new PIN/PUK is wrong, this command must fail.
    // - If the format is bad, the applet can choose whether to decrement or not.
    //
    // IMPLEMENTATION NOTES:
    // - This applet decrements if the old PIN/PUK is the wrong value
    // (implemented in verify()).
    // - This applet does not decrement if the format of either PIN/PUK is wrong.

    // PRE-CONDITION 1: The requested verifier must be defined
    PIVVerifier verifier = dataStore.getVerifier(id);
    if (verifier == null) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 2: The verifier must be permitted
    checkAccessPrivilege(verifier, pApdu);

    // PRE-CONDITION 3: The 'RESTRICT UPDATE' flag must be false for this verifier
    if (verifier.getRestrictUpdate()) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    // PRE-CONDITION 4: Ensure the supplied length is exactly two maximum lengths
    byte maxLength = verifier.getMaxLength();
    if (length != (short) (maxLength * 2)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // If the authentication data in the command data field satisfies the criteria
    // in Section 2.4.3 and matches the current value of the reference data, but
    // the new reference data in the command data field of the command does not
    // satisfy the criteria in Section 2.4.3, the PIV Card Application shall
    // return status word '6A 80'.
    //
    // TRANSLATION:
    // - If [Old PIN is GOOD] but [New PIN format is BAD], use 6A80 and do not
    // decrement.
    //

    // If the new reference data (PIN) in the command data field of the command
    // does not satisfy the criteria in Section 2.4.3, then the PIV Card
    // Application shall return the status word '6A80'.
    //
    // TRANSLATION:
    // - Again, if the format of the new PIN is bad, fail without decrementing.

    // If the authentication data in the command data field does not match the
    // current value of the reference data, but both the authentication data and
    // the new reference data in the command data field of the command satisfy
    // the criteria in Section 2.4.3, the PIV Card Application shall return
    // status word '63 CX'.
    // If status word '6A 80' is returned, the security status and retry counter
    // associated with the key reference shall remain unchanged. If status word
    // '63 CX' is returned, the security status of the key reference shall be set
    // to FALSE and the retry counter associated with the key reference shall be
    // decremented by one.
    //
    // TRANSLATION:
    // - If the old PIN/PUK format is GOOD, but the value is BAD, fail and
    // decrement.

    // PRE-CONDITION 5 - The old PIN/PUK value must verify successfully
    verify(VERIFY_MODE_AUTH, id, pApdu, maxLength);

    // PRE-CONDITION 6 - The supplied id must now be verified    
    if (!verifier.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the security status of the key reference
    // shall be set to TRUE and the retry counter associated with the key reference
    // shall be set to the reset retry value associated with the key reference.
    //
    // TRANSLATION:
    // - If the change is successful, that PIN/Operator is considered authenticated.
    offset += maxLength;

    // STEP 1 - Update the PIN
    verifier.update(buffer, offset, maxLength);

    // STEP 2 - Verify the new PIN, which will have the effect of setting it to TRUE
    // and resetting the retry counter.
    verifier.check(buffer, offset, maxLength);

    // Indicate we have no response data    
    pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
  }

  /**
   * The RESET RETRY COUNTER card command resets the retry counter of the PIN to its initial value
   * and changes the reference data. The command enables recovery of the PIV Card Application PIN in
   * the case that the cardholder has forgotten the PIV Card Application PIN.
   *
   * @param id     The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void resetRetryCounter(byte id, PIVAPDU pApdu) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1: The supplied ID must be the Card PIN
    // The only key reference allowed in the P2 parameter of the RESET RETRY COUNTER
    // command is the PIV Card Application PIN. If a key reference is specified in P2
    // that is not supported by the card, the PIV Card Application shall return the
    // status word '6A 88'.
    if (id != Constants.ID_AUTH_LOCAL_PIN && id != Constants.ID_AUTH_GLOBAL_PIN) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION 2: The requested verifier must be defined
    PIVVerifier target = dataStore.getVerifier(id);
    if (target == null) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 3: The verifier must be permitted
    checkAccessPrivilege(target, pApdu);

    // PRE-CONDITION 4: The 'RESTRICT UPDATE' flag must be false for this verifier
    if (target.getRestrictUpdate()) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION 5: The PUK must be defined
    PIVVerifier puk = dataStore.getVerifier(Constants.ID_AUTH_PUK);
    if (puk == null) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 6: The verifier must be permitted
    checkAccessPrivilege(puk, pApdu);

    // If the reset retry counter authentication data (PUK) in the command data
    // field of the command does not match reference data associated with the PUK
    // and the new reference data (PIN) in the command data field of the command
    // does not satisfy the criteria in Section 2.4.3, then the PIV Card
    // Application shall return either status word '6A 80' or '63 CX'.
    //
    // If the PIV Card Application returns status word '6A 80', then the retry
    // counter associated with the PIN shall not be reset, the security status
    // of the PIN's key reference shall remain unchanged, and the PUK's retry
    // counter shall remain unchanged.
    //
    // If the PIV Card Application returns status word '63 CX', then the retry
    // counter associated with the PIN shall not be reset, the security status
    // of the PIN's key reference shall be set to FALSE, and the PUK's retry
    // counter shall be decremented by one.
    //
    // TRANSLATION:
    // - If the PUK value is wrong AND the new PIN format is bad, we can choose
    // to just say WRONG DATA or not without checking the PUK.
    //
    // IMPLEMENTATION NOTES:
    // - We check the new PIN format first, so we DO NOT check or decrement the
    // PUK if the new format is bad.

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    // PRE-CONDITION 7: The supplied length must equal the PUK + NEW PIN lengths
    if (length != (short) (puk.getMaxLength() + target.getMaxLength())) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 8: The supplied PUK value must verify successfully
    // NOTE: verify() will check the operator integrity automatically
    verify(VERIFY_MODE_AUTH, Constants.ID_AUTH_PUK, pApdu, puk.getMaxLength());

    // PRE-CONDITION 9: The SECURITY_OFFICER role must now be present
    if (!operator.hasRole(Operator.ROLE_SECURITY_OFFICER)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the PIN's retry counter shall be set to
    // its reset retry value. Optionally, the PUK's retry counter may be set to its
    // initial reset retry value.
    // - The security status of the PIN's key reference shall \not be changed.

    // NOTE:
    // - Since the PUK was verified, the OwnerPIN object automatically resets the
    // PUK counter, which governs the above behaviour.

    // Update, reset and unblock the PIN
    offset += puk.getMaxLength();
    target.update(buffer, offset, target.getMaxLength());

    // Indicate we have no response data    
    pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
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
  void generalAuthenticate(byte id, byte mechanism, PIVAPDU pApdu) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key reference and mechanism must point to an existing
    // key
    PIVKey key = dataStore.getKey(id, mechanism);

    if (key == null) {
      // If any key reference value is specified that is not supported by the card,
      // the PIV Card Application shall return the status word '6A 88'.
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 2 - The access rules must be satisfied for the requested key
    // NOTE: A call to this method automatically clears the PIN ALWAYS status.
    checkAccessPrivilege(key, pApdu);

    // PRE-CONDITION 3 - The key's private or secret values must have been set
    if (!key.isInitialised()) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      return; // Keep compiler happy
    }

    // Set up our TLV reader
    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();
    TLVReader reader = TLVReader.getInstance(buffer, offset, length);

    // PRE-CONDITION 4 - The Dynamic Authentication Template tag must be present in
    // the data
    if (!reader.match(Constants.TAG_AUTH_TEMPLATE)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return; // Keep compiler happy
    }
    reader.moveInto(); // Move into the content of the template

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Traverse the TLV to determine what combination of elements exist
    //
    short challengeOffset = Constants.ZERO_SHORT;
    short witnessOffset = Constants.ZERO_SHORT;
    short responseOffset = Constants.ZERO_SHORT;
    short exponentiationOffset = Constants.ZERO_SHORT;

    short challengeLength = Constants.ZERO_SHORT;
    short witnessLength = Constants.ZERO_SHORT;
    short responseLength = Constants.ZERO_SHORT;
    short exponentiationLength = Constants.ZERO_SHORT;

    // Loop through all tags
    do {
      switch (reader.getTag()) {
      case Constants.TAG_AUTH_CHALLENGE:
        challengeOffset = reader.getDataOffset();
        challengeLength = reader.getLength();
        break;
      case Constants.TAG_AUTH_CHALLENGE_RESPONSE:
        responseOffset = reader.getDataOffset();
        responseLength = reader.getLength();
        break;
      case Constants.TAG_AUTH_WITNESS:
        witnessOffset = reader.getDataOffset();
        witnessLength = reader.getLength();
        break;
      case Constants.TAG_AUTH_EXPONENTIATION:
        exponentiationOffset = reader.getDataOffset();
        exponentiationLength = reader.getLength();
        break;

      default:
        // We have come across an unknown tag value. Other implementations ignore these
        // and so shall
        // we.
        break;
      }
    } while (reader.moveNext());

    //
    // STEP 2 - Process the appropriate GENERAL AUTHENTICATE case
    //

    short outLength = 0;

    //
    // IMPLEMENTATION NOTES
    // --------------------
    // There are 6 authentication cases that make up all of the GENERAL AUTHENTICATE
    // functionality.
    // The first case (Internal Authenticate) has 4 different mode variants
    // depending on the key
    // type and attributes.
    //
    // CASE 1 - INTERNAL AUTHENTICATE
    //
    // Description:
    // The CLIENT presents a CHALLENGE to the CARD, which then returns the
    // encrypted/signed
    // CHALLENGE RESPONSE. This is handled in 3 different mode variants, depending
    // on the keys.
    // a. TDEA/AES keys with the SIGNATURE role will encipher the challenge.
    // b. RSA/ECC keys with the SIGNATURE role will perform signing operations
    // (on already padded data).
    // c. SM keys with the KEY_ESTABLISH role will perform the Opacity-ZKM key
    // agreement
    // All other cases are invalid
    //
    // Pre-conditions:
    // 1) A CHALLENGE is present with data; AND
    // 2) A RESPONSE is present but empty; AND
    // 3) A WITNESS is NOT present; AND
    // 4) An EXPONENTIATION is NOT present; AND
    // 5a) If the key type is ECC and has the KEY_ESTABLISH role, it is Variant A
    // 5b) If the key type is RSA or ECC has the SIGNATURE role, it is Variant B
    // 5c) If the key type is RSA and has the KEY_ESTABLISH role, it is Variant C
    // 5d) If the key type is TDEA or AES and has the AUTHENTICATE role, it is
    // Variant D    
    if (challengeOffset != 0 && challengeLength != 0 && responseOffset != 0 && responseLength == 0 && witnessOffset == 0
        && exponentiationOffset == 0) {
      // Variant A - Secure Messaging; AND
      // Variant C - RSA Key Transport
      if (key.hasRole(PIVKey.ROLE_KEY_ESTABLISH)) {
        if (key instanceof PIVKeySM) {
          // Variant A
          outLength = generalAuthenticateCase1A((PIVKeySM) key, buffer, challengeOffset, challengeLength);
        } else if (key instanceof PIVKeyRSA) {
          // Variant C
          outLength = generalAuthenticateCase1C((PIVKeyRSA) key, buffer, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant B - Digital Signatures
      else if (key.hasRole(PIVKey.ROLE_SIGN)) {
        if (key instanceof PIVKeyPKI) {
          outLength = generalAuthenticateCase1B((PIVKeyPKI) key, buffer, challengeOffset, challengeLength);
        } else if (key instanceof PIVKeySYM) {
          outLength = generalAuthenticateCase1D((PIVKeySYM) key, buffer, challengeOffset, challengeLength);
        } else {
          // Insane code path (this cannot be reached in normal conditions)
          authenticateReset();
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Invalid case
      else {
        authenticateReset();
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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
    // 2) A RESPONSE is NOT present; AND
    // 3) A WITNESS is NOT present; AND
    // 4) An EXPONENTIATION is NOT present; AND
    // 5) The key type is SYMMETRIC
    //
    // The client requests a CHALLENGE from the CARD, which returns the CHALLENGE in
    // plaintext
    else if (challengeOffset != 0 && challengeLength == 0 && responseOffset == 0 && witnessOffset == 0
        && exponentiationOffset == 0) {
      if (key instanceof PIVKeySYM) {
        outLength = generalAuthenticateCase2((PIVKeySYM) key, buffer, pApdu);
      } else {
        authenticateReset();
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
    // 2) A CHALLENGE is NOT present; AND
    // 3) A WITNESS is NOT present; AND
    // 4) An EXPONENTIATION is NOT present; AND
    // 5) The key type is SYMMETRIC
    else if (responseOffset != 0 && responseLength != 0 && challengeOffset == 0 && witnessOffset == 0
        && exponentiationOffset == 0) {
      if (key instanceof PIVKeySYM) {
        outLength = generalAuthenticateCase3((PIVKeySYM) key, buffer, responseOffset, responseLength);
      } else {
        authenticateReset();
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //
    // Description:
    // The client requests a WITNESS (a proof of key posession) from the CARD. The
    // card generates the WITNESS, encrypts it and returns it as ciphertext.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present but empty
    // 2) A CHALLENGE is NOT present; AND
    // 3) A RESPONSE is NOT present; AND
    // 4) An EXPONENTIATION is NOT present; AND
    // 5) The key has the AUTHENTICATE role set
    //
    else if (witnessOffset != 0 && witnessLength == 0 && challengeOffset == 0 && responseOffset == 0
        && exponentiationOffset == 0) {
      if (key instanceof PIVKeySYM) {
        outLength = generalAuthenticateCase4((PIVKeySYM) key, buffer, pApdu);
      } else {
        authenticateReset();
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //
    // Description:
    // The client decrypts the received WITNESS, generates a CHALLENGE REQUEST and
    // presents both to
    // the CARD. The card verifies the decrypted WITNESS and encrypts the CHALLENGE,
    // which it then
    // returns as the CHALLENGE RESPONSE.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present with data; AND
    // 2) A CHALLENGE is present with data; AND
    // 3) A RESPONSE is NOT present; AND
    // 4) An EXPONENTIATION is NOT present; AND
    // 5) The key type is SYMMETRIC
    else if (witnessOffset != 0 && witnessLength != 0 && challengeOffset != 0 && challengeLength != 0
        && responseOffset == 0 && exponentiationOffset == 0) {
      if (key instanceof PIVKeySYM) {
        outLength = generalAuthenticateCase5((PIVKeySYM) key, buffer, witnessOffset, witnessLength, challengeOffset,
            challengeLength);
      } else {
        authenticateReset();
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    }

    //
    // CASE 6 - KEY ESTABLISHMENT SCHEME
    //
    // Description:
    // The client supplies a valid ECC public key and the CARD generates a shared
    // secret key.
    //
    // Pre-Conditions:
    // 1) An EXPONENTIATION parameter is present with data
    // 2) A RESPONSE is present but empty AND
    // 3) A WITNESS is NOT present; AND
    // 4) A CHALLENGE is NOT present; AND
    // 5) The key type is ECC
    else if (exponentiationOffset != 0 && exponentiationLength != 0 && witnessOffset == 0 && challengeOffset == 0
        && responseOffset != 0 && responseLength == 0) {
      if (key instanceof PIVKeyECC) {
        outLength = generalAuthenticateCase6((PIVKeyECC) key, buffer, exponentiationOffset, exponentiationLength);
      } else {
        authenticateReset();
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    // If any other tag combination is present in the first element of data, it is
    // an invalid case.
    else {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Process any outgoing data
    if (outLength > 0) {
      pApdu.setOutgoingAPDU(Constants.ZERO_SHORT, outLength);
    } else {
      pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
    }
  }

  // Variant A - Secure Messaging
  private short generalAuthenticateCase1A(PIVKeySM key, byte[] buffer, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    // Check operator integrity
    operator.performIntegrityCheck();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: There must NOT be an already established Secure Channel
    if (operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    //
    // Execution Steps
    //    

    // STEP 1 - If the pairing code exists, reset it automatically
    PIVVerifier pc = dataStore.getVerifier(Constants.ID_AUTH_PAIRING_CODE);
    if (pc != null && pc.isValidated()) {
      pc.reset();
    }

    // STEP 2 - Execute the PIV Secure Messaging key establishment mechanism
    short expectedLength = channelPIVSM.getEstablishResponseLength(key);

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, expectedLength, Constants.TAG_AUTH_TEMPLATE);
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);

    short offset = writer.getOffset();
    if (expectedLength <= TLV.LENGTH_1BYTE_MAX) {
      // Single-byte form
      offset += TLV.LENGTH_1BYTE;
    } else if (expectedLength <= TLV.LENGTH_2BYTE_MAX) {
      // Double-byte form
      offset += TLV.LENGTH_2BYTE;
    } else {
      // Triple-byte form
      offset += TLV.LENGTH_3BYTE;
    }

    short length;
    try {
      length = channelPIVSM.establish(key, buffer, challengeOffset, challengeLength, buffer, offset);
    } catch (CryptoException e) {
      authenticateReset();
      channelPIVSM.reset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    } catch (CardRuntimeException e) {
      authenticateReset();
      channelPIVSM.reset();
      ISOException.throwIt(e.getReason());
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    // The writer object is still pointing to where the length needs to be written,
    // so we can write the length
    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our
    // data. If not, something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      channelPIVSM.reset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    // Now we can move past the signature data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // DONE: The buffer now contains CBICC | NICC | AuthCryptogramICC | cICC at offset ZERO
    return length;
  }

  // Variant B - Digital Signatures
  private short generalAuthenticateCase1B(PIVKeyPKI key, byte[] buffer, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // NONE

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the signature until we do it. Since we could be
    // writing a short-form length (ECC) or long-form (RSA), the TLV header could be either
    // 4 or 8 bytes long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTES:
    // You might be thinking "but if you know the algorithm and key size, you know the length!".
    // You would be right, but unfortunately some implementations put a leading '00' byte in
    // front of their signature data and some don't, so we just wait until we know exactly. It
    // might seem like a pain but it does save an array copy and prevents use of the APDU buffer,
    // so we think it's worth it.
    //
    // MECHANISM CASES:
    // ECC256 - Challenge block is 32 bytes and Signature is 64-70 bytes (single-byte length)
    // ECC384 - Challenge block is 48 bytes and Signature is 96-102 bytes (single-byte length)
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes (triple-byte length)
    // RSA3072 - Challenge block is 384 bytes and Signature is 384 bytes (triple-byte length)
    // RSA4096 - Challenge block is 512 bytes and Signature is 512 bytes (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - Given the above cases, if the challenge length is less than 127, we can categorise it
    //   as a TLV short form length.
    // - RSA1024 should not be permitted for this operation, but that should be restricted using
    //   key roles rather than here.

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, challengeLength, Constants.TAG_AUTH_TEMPLATE);
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);

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
      length = key.sign(buffer, challengeOffset, challengeLength, buffer, offset);
    } catch (Exception e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written,
    // so we can write the length
    //
    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our
    // data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    // Now we can move past the signature data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Done, return the length of data we are sending
    return length;
  }

  // Variant C - RSA Key Transport
  private short generalAuthenticateCase1C(PIVKeyRSA key, byte[] buffer, short challengeOffset, short challengeLength)
      throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block
    // length
    if (challengeLength != key.getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of
    // the same
    // scratch buffer and perform the cipher in-place. This saves us from using the
    // APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the data until we do it. Since we could be
    // writing
    // a short-form length (ECC) or long-form (RSA), the TLV header could be either
    // 4 or 8 bytes
    // long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we
    // know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTE:
    // You might be thinking "but if you know the algorithm and key size, you know
    // the length!".
    // You would be right, but unfortunately some implementations put a leading '00'
    // byte in front
    // of their signature data and some don't, so we just wait until we know
    // exactly. It might
    // seem like a pain but it does save an array copy and prevents use of the APDU
    // buffer, so
    // we think it's worth it.
    //

    //
    // MECHANISM CASES:
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes
    // (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes
    // (triple-byte length)
    // RSA3072 - Challenge block is 384 bytes and Signature is 384 bytes
    // (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - ECC keys are not valid for this case

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, challengeLength, Constants.TAG_AUTH_TEMPLATE);
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);

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
      length = key.keyEstablish(buffer, challengeOffset, challengeLength, buffer, offset);
    } catch (Exception e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written,
    // so
    // we can write the length
    //
    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our
    // data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    // Now we can move past the decrypted data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Done, return the length of data we are sending
    return length;
  }

  // Variant D - Symmetric Internal Authentication
  private short generalAuthenticateCase1D(PIVKeySYM key, byte[] buffer, short challengeOffset, short challengeLength)
      throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // NONE

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block
    // length
    if (challengeLength != key.getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of
    // the same
    // scratch buffer and perform the cipher in-place. This saves us from using the
    // APDU
    // buffer as a temporary working space and performing an extra copy.
    //

    // Write out the response TLV, passing through the challenge length as an
    // indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, challengeLength, Constants.TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);

    // Encrypt the CHALLENGE data
    short offset = writer.getOffset();
    try {
      offset += key.encipher(buffer, challengeOffset, challengeLength, buffer, offset);
    } catch (Exception e) {
      authenticateReset();

      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Finalise the TLV object and get the entire data object length
    writer.setOffset(offset);

    // Done, return the length of data we are sending
    return writer.finish();
  }

  private short generalAuthenticateCase2(PIVKeySYM key, byte[] buffer, PIVAPDU pApdu) throws ISOException {

    //
    // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
    // Authenticates the HOST to the CARD
    //

    // > Client application requests a challenge from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Check operator integrity
    operator.performIntegrityCheck();

    //
    // PRE-CONDITIONS
    //

    // Now we explicitly clear any existing authentication state first
    operator.clearRole(Operator.ROLE_KEY_HOLDER);

    // PRE-CONDITION 1: If PUK and VCI COMPATIBILITY MODE is disabled, it cannot be used over VCI
    // NOTE: Under no circumstances does the PIV standard permit admin key auth over contactless
    if (!config.readFlag(Config.CONFIG_VCI_COMPATIBILITY_MODE) && Platform.isContactless()
        && isVirtualContactInterface(pApdu)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key must have the correct role
    if (!key.hasRole(PIVKey.ROLE_AUTHENTICATE)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The key MUST have the PERMIT EXTERNAL attribute set
    if (!key.hasAttribute(PIVKey.ATTR_PERMIT_EXTERNAL)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short length = key.getBlockLength();

    // Write out the response TLV, passing through the block length as an indicative
    // maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, length, Constants.TAG_AUTH_TEMPLATE);

    // Create the CHALLENGE tag
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE);
    writer.writeLength(key.getBlockLength());

    // Generate the CHALLENGE data and write it to the output buffer
    short offset = writer.getOffset();
    Platform.Cryptography.generateRandom(buffer, offset, length);

    try {
      // Generate and store the encrypted CHALLENGE in our context, so we can compare
      // it without the key reference later.
      offset += key.encipher(buffer, offset, length, generalAuthState, OFFSET_GA_CHALLENGE);
    } catch (Exception e) {
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return Constants.ZERO_SHORT; // Keep static analyser happy
    }

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set our authentication state to EXTERNAL
    generalAuthState[OFFSET_GA_STATE] = GA_STATE_EXTERNAL;
    generalAuthState[OFFSET_GA_ID] = key.getKeyId();
    generalAuthState[OFFSET_GA_MECHANISM] = key.getMechanism();

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase3(PIVKeySYM key, byte[] buffer, short responseOffset, short responseLength)
      throws ISOException {

    //
    // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
    //

    // > Client application responds to a challenge from the PIV Card Application.

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is
    // EXTERNAL
    if (generalAuthState[OFFSET_GA_STATE] != GA_STATE_EXTERNAL) {
      // Invalid state for this command
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have
    // not changed
    if (generalAuthState[OFFSET_GA_ID] != key.getKeyId()
        || generalAuthState[OFFSET_GA_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }

    // PRE-CONDITION 3 - The RESPONSE tag length must be the same as our block
    // length
    if (responseLength != key.getBlockLength()) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Compare the authentication statuses
    if (!Platform.arrayCompare(buffer, responseOffset, generalAuthState, OFFSET_GA_CHALLENGE, responseLength)) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Immediately reset our authentication state
    authenticateReset();

    // Check operator integrity
    operator.performIntegrityCheck();

    // We are now authenticated and the CM role against this key
    operator.setRoleAndId(Operator.ROLE_KEY_HOLDER, key.getKeyId());

    // Done, no data to return
    return Constants.ZERO_SHORT;
  }

  private short generalAuthenticateCase4(PIVKeySYM key, byte[] buffer, PIVAPDU pApdu) throws ISOException {

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //

    // > Client application requests a WITNESS from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Check operator integrity
    operator.performIntegrityCheck();

    //
    // PRE-CONDITIONS
    //

    // Clear any existing authentication state
    operator.clearRole(Operator.ROLE_KEY_HOLDER);

    // PRE-CONDITION 1: If PUK and VCI COMPATIBILITY MODE is disabled, it cannot be used over VCI
    // NOTE: Under no circumstances does the PIV standard permit admin key auth over contactless
    if (!config.readFlag(Config.CONFIG_VCI_COMPATIBILITY_MODE) && Platform.isContactless()
        && isVirtualContactInterface(pApdu)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKey.ROLE_AUTHENTICATE)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT MUTUAL attribute set
    if (!key.hasAttribute(PIVKey.ATTR_PERMIT_MUTUAL)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // < PIV Card Application returns a WITNESS that is created by generating random
    // data and encrypting it using the referenced key

    // Generate a block length worth of WITNESS data
    short length = key.getBlockLength();
    Platform.Cryptography.generateRandom(generalAuthState, OFFSET_GA_CHALLENGE, length);

    // Write out the response TLV, passing through the block length as an indicative
    // maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, length, Constants.TAG_AUTH_TEMPLATE);

    // Create the WITNESS tag
    writer.writeTagByte(Constants.TAG_AUTH_WITNESS);
    writer.writeLength(length);

    // Encrypt the WITNESS data and write it to the output buffer
    short offset = writer.getOffset();
    offset += key.encipher(generalAuthState, OFFSET_GA_CHALLENGE, length, buffer, offset);
    writer.setOffset(offset); // Update the TLV offset value

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Update our authentication status, id and mechanism
    generalAuthState[OFFSET_GA_STATE] = GA_STATE_MUTUAL;
    generalAuthState[OFFSET_GA_ID] = key.getKeyId();
    generalAuthState[OFFSET_GA_MECHANISM] = key.getMechanism();

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase5(PIVKeySYM key, byte[] buffer, short witnessOffset, short witnessLength,
      short challengeOffset, short challengeLength) throws ISOException {

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //

    //
    // PRE-CONDITIONS
    //

    // < PIV Card Application authenticates the client application by verifying the
    // decrypted
    // witness.

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is
    // MUTUAL
    if (generalAuthState[OFFSET_GA_STATE] != GA_STATE_MUTUAL) {
      // Invalid state for this command
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have
    // not changed
    if (generalAuthState[OFFSET_GA_ID] != key.getKeyId()
        || generalAuthState[OFFSET_GA_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }

    // PRE-CONDITION 3 - The WITNESS tag length must be the same as our block length
    if (witnessLength != key.getBlockLength()) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The CHALLENGE tag length must be equal to the witness length
    if (challengeLength != witnessLength) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses   
    if (!Platform.arrayCompare(buffer, witnessOffset, generalAuthState, OFFSET_GA_CHALLENGE, witnessLength)) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: The WITNESS is now verified, on to the CHALLENGE

    // > Client application requests encryption of CHALLENGE data from the card
    // using the same key.

    // Write out the response TLV, passing through the block length as an indicative
    // maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, challengeLength, Constants.TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);
    short offset = writer.getOffset();

    // Encrypt the CHALLENGE data
    offset += key.encipher(buffer, challengeOffset, challengeLength, buffer, offset);

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    short length = writer.finish();

    // Check operator integrity
    operator.performIntegrityCheck();

    // Set this key's authentication state
    operator.setRoleAndId(Operator.ROLE_KEY_HOLDER, key.getKeyId());

    // Clear our authentication state
    authenticateReset();

    // < PIV Card Application indicates successful authentication and sends back the encrypted 
    // challenge.

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase6(PIVKeyECC key, byte[] buffer, short exponentiationOffset,
      short exponentiationLength) throws ISOException {

    //
    // CASE 6 - ECDH Key Agreement
    //

    // > Client application returns the ECDH derived shared secret

    // Reset any other authentication intermediate state
    authenticateReset();

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKey.ROLE_KEY_ESTABLISH)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The EXPONENTIATION tag length must be the same as our block
    // length
    // NOTE: This is checked by the underlying implementation now
    short length = key.getPublicPointLength();

    // Write out the response TLV, passing through the block length as an indicative
    // maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, length, Constants.TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTagByte(Constants.TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(key.getKeyLengthBytes());

    // Compute the shared secret
    try {
      length = key.keyEstablish(buffer, exponentiationOffset, exponentiationLength, buffer, writer.getOffset());
    } catch (CryptoException ex) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Move to the end of the key agreement output data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // < PIV Card Application indicates successful authentication and sends back the
    // encrypted
    // challenge.

    // Done, return the length of data we are sending
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
  void generateKeyPair(byte id, PIVAPDU pApdu) throws ISOException {

    // Request Elements
    final byte CONST_TAG_TEMPLATE = (byte) 0xAC;
    final byte CONST_TAG_MECHANISM = (byte) 0x80;

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    //
    // PRE-CONDITIONS
    //
    TLVReader reader = TLVReader.getInstance(buffer, offset, length);

    // PRE-CONDITION 1 - The 'TEMPLATE' tag must be present in the supplied buffer
    if (!reader.match(CONST_TAG_TEMPLATE)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    reader.moveInto();

    // PRE-CONDITION 2 - The 'MECHANISM' tag must be present in the supplied buffer
    if (!reader.match(CONST_TAG_MECHANISM)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 3 - The 'MECHANISM' tag must have a length of 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // We now read this element in as the mechanism. I am sure there was a good
    // reason
    // why this couldn't have just been the P1 value!
    byte mechanism = reader.toByte();

    //
    // NOTES:
    // - We ignore the existence of the 'PARAMETER' tag, because according to
    // SP800-78-4
    // the RSA public exponent is now fixed to 65537 (Section 3.1 PIV Cryptographic
    // Keys)
    // - ECC keys have no parameter.

    // PRE-CONDITION 4A - The key reference and mechanism must exist (key test)
    if (dataStore.getKey(id) == null) {
      // The key reference is bad
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 4B - For the PIV-SM key, if the generic ECC mechanism is supplied,
    // map it to the appropriate cipher suite.
    // NOTE: This is required because although the algorithm identifiers for PIV-SM keys are 
    // '27' (P256) & '2E' (P384), for the GEN ASYM KEYPAIR command only the PIV Test Runner wants 
    // the original ECCP256 ('11') and ECCP384 ('14') identifiers specified. This implies that 
    // other PIV implementations with PIV-SM probably do the same thing and so shall we.
    if (id == Config.DEFAULT_PIVSM_KEY && mechanism == Constants.ID_ALG_ECC_P256) {
      mechanism = Constants.ID_ALG_ECC_CS2;
    }    
    if (id == Config.DEFAULT_PIVSM_KEY && mechanism == Constants.ID_ALG_ECC_P384) {
      mechanism = Constants.ID_ALG_ECC_CS7;
    }    
    
    // PRE-CONDITION 4C - The key reference and mechanism must exist (mechanism
    // test)
    PIVKey key = dataStore.getKey(id, mechanism);
    if (key == null) {
      // NOTE: The error message we return here is different dependant on whether the
      // key is bad
      // (6A86), or the mechanism is bad (6A80) (See SP800-73-4 3.3.2 Generate
      // Asymmetric Key pair).
      // The mechanism is bad
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 5 - The key must be an asymmetric key (key pair)
    if (!(key instanceof PIVKeyPKI)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return; // Keep static analyser happy
    }

    // PRE-CONDITION 6 - The access rules must be satisfied for administrative access
    checkWritePrivilege(key, pApdu);

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Generate the key pair
    PIVKeyPKI keyPair = (PIVKeyPKI) key;
    length = keyPair.generate(buffer, Constants.ZERO_SHORT);

    // STEP 2 - Configure the APDU handler to process the outgoing data
    pApdu.setOutgoingAPDU(Constants.ZERO_SHORT, length);
  }

  /*
   * Returns true if one of the following is true; 1) The current interface is considered to be
   * contact for the purposes of access control. 2) The applet option RESTRICT_CONTACTLESS_GLOBAL is
   * not set
   */
  boolean isInterfacePermitted() {
    // Operation is only allowed over the contactless interface if the 
    // CONFIG_RESTRICT_CONTACTLESS_GLOBAL flag is NOT SET.
    return !Platform.isContactless() || !config.readFlag(Config.CONFIG_RESTRICT_CONTACTLESS_GLOBAL);
  }

  /***
   * Indicates whether administration is allowed over the current communications media. Note that
   * this DOES NOT mean there is a valid administrative session!
   *
   * @return True if administrative commands are permitted in the current context.
   */
  boolean isInterfacePermittedForAdmin() {
    // Administration is only allowed over the contactless interface if the
    // CONFIG_RESTRICT_CONTACTLESS_ADMIN flag is NOT SET
    return !Platform.isContactless() || !config.readFlag(Config.CONFIG_RESTRICT_CONTACTLESS_ADMIN);
  }

  /**
   * Clears any intermediate authentication status used by 'GENERAL AUTHENTICATE'
   */
  private void authenticateReset() throws ISOException {
    // FIPS140
    Platform.zeroise(generalAuthState, Constants.ZERO_SHORT, LENGTH_GA_STATE);
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

  private void processCreateObjectRequest(byte operation, TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(Constants.TAG_OBJECT_ID)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag have length between 1 and 3
    short tagLength = reader.getLength();
    if (tagLength < Constants.OBJECT_ID_MIN_LENGTH || tagLength > Constants.OBJECT_ID_MAX_LENGTH) {
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }

    // Use the last byte of the value as the identifier
    int id = PIVContainer.parseId(reader.getData(), reader.getDataOffset(), tagLength);
    reader.moveNext();

    // PRE-CONDITION 3 - The 'MODE CONTACT' tag MUST be present
    if (!reader.match(Constants.TAG_MODE_CONTACT)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACT_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'MODE CONTACT' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
      return;
    }

    byte modeContact = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5 - The 'MODE CONTACTLESS' tag MUST be present
    if (!reader.match(Constants.TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
      return;
    }

    // PRE-CONDITION 6 - The 'MODE CONTACTLESS' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
      return;
    }

    byte modeContactless = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 7 - The 'ADMIN KEY' tag MAY be present
    byte adminKey = (byte) 0;
    if (reader.match(Constants.TAG_ADMIN_KEY)) {

      // PRE-CONDITION 8 - If the 'ADMIN KEY' tag is present, it MUST be length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(Constants.SW_PUT_DATA_ADMIN_KEY_INVALID_LENGTH);
        return;
      }

      adminKey = reader.toByte();
      reader.moveNext();
    }

    //
    // Call the appropriate creation pattern
    //

    switch (operation) {

    case Constants.TAG_OP_CREATE_CONTAINER:
      // PRE-CONDITION - Make sure it doesn't exist
      if (dataStore.getContainer(id) != null) {
        ISOException.throwIt(Constants.SW_PUT_DATA_OBJECT_EXISTS);
      }

      // Create our new container
      PIVContainer container = new PIVContainer(id, modeContact, modeContactless, adminKey);

      // Add it to our store
      dataStore.addContainer(container);
      break;

    case Constants.TAG_OP_CREATE_VERIFIER:

      // PRE-CONDITION - Make sure it doesn't exist
      if (dataStore.getVerifier((byte) id) != null) {
        ISOException.throwIt(Constants.SW_PUT_DATA_OBJECT_EXISTS);
      }

      // Create our new key
      PIVVerifier verifier = PIVVerifier.createVerifier(id, modeContact, modeContactless, reader);

      // Add it to our store
      dataStore.addVerifier(verifier);
      break;

    case Constants.TAG_OP_CREATE_KEY:
      //
      // For keys, we cannot check the id only first because it is possible for multiple ID's to
      // exist with different mechanisms (9E PKI and 9E Symmetric being an IRL example). 
      //

      // Create our new key
      PIVKey key = PIVKey.createKey(id, modeContact, modeContactless, adminKey, reader);
      byte mechanism = key.getMechanism();

      // PRE-CONDITION - Make sure it doesn't exist
      if (dataStore.getKey((byte) id, mechanism) != null) {
        // Since we have already created the object, kill it and request deletion
        // This isn't elegant but most likely won't have any impact in a production sense. 
        key = null;
        Platform.requestObjectDeletion();
        ISOException.throwIt(Constants.SW_PUT_DATA_OBJECT_EXISTS);
      }

      // Lazy initialisation of PIV Secure Messaging. The first of these algorithms to be
      // used when creating key with the PIV SM identifier will be the option supported by the applet.
      if (!channelPIVSM.isInitialised() && id == Config.DEFAULT_PIVSM_KEY
          && (mechanism == Constants.ID_ALG_ECC_CS2 || mechanism == Constants.ID_ALG_ECC_CS7)) {
        channelPIVSM.init(mechanism);
      }

      // Add it to our store
      dataStore.addKey(key);
      break;

    default:
      ISOException.throwIt(Constants.SW_PUT_DATA_OP_INVALID_VALUE);
      break;
    }
  }

  /**
   * This is the administrative equivalent for the PUT DATA card and is intended for use by Card
   * Management Systems to generate the on-card file-system.
   *
   * @param buffer - The incoming APDU buffer
   * @param offset - The starting offset of the CDATA section
   * @param length - The length of the CDATA section
   */
  void putDataAdmin(PIVAPDU pApdu) throws ISOException {

    //
    // SECURITY PRE-CONDITION
    //

    // Check operator integrity
    operator.performIntegrityCheck();

    // PRE-CONDITION 1: This applet must not be in the SECURED state.
    if (OpenFIPS201.getAppletSecuredState()) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    // PRE-CONDITION 2: The command must have been sent over SCP with CEnc+CMac
    if (pApdu.getSecureChannel() != PIVAPDU.SECURE_CHANNEL_SCP || !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: We don't check here whether the interface is permitted for
    // administration anymore because it is not possible to establish a secure
    // channel without
    // this being permitted.

    //
    // PRE-PROCESSING
    //

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    // Initialise our TLV reader
    TLVReader reader = TLVReader.getInstance(buffer, offset, length);

    // If the top-level tag indicates this is a BULK request, we move into it and
    // then we are left
    // with an array of objects. If it doesn't, we are already at the start of the
    // only request.
    boolean isBulk;
    if (reader.match(Constants.TAG_OP_BULK_REQUEST)) {
      isBulk = true;
      reader.moveInto();
    } else {
      isBulk = false;
    }

    // Loop through all the requests
    do {
      // Get the operation value
      byte operation = reader.getTag();

      // Move into the constructed tag
      reader.moveInto();

      switch (operation) {

      // Create a PIV object (Container, Verifier, Key)
      case Constants.TAG_OP_CREATE_CONTAINER:
      case Constants.TAG_OP_CREATE_VERIFIER:
      case Constants.TAG_OP_CREATE_KEY:
        processCreateObjectRequest(operation, reader);
        break;

      // Update one or more configuration parameters
      case Constants.TAG_OP_UPDATE_CONFIG:
        try {
          Platform.beginTransaction();
          config.update(reader);
          Platform.commitTransaction();
        } catch (ISOException ex) {
          Platform.abortTransaction();
          ISOException.throwIt(ex.getReason());
        } catch (Exception ex) {
          Platform.abortTransaction();
          ISOException.throwIt(Constants.SW_PUT_DATA_CONFIG_INVALID_VALUE);
        }
        break;

      // Transition the applet to the 'SECURED' state, which will disable this
      // command.
      case Constants.TAG_OP_SECURE_APPLET:
        //
        // Once this is successfully processed, any further calls to PUT DATA ADMIN will
        // fail.
        //
        OpenFIPS201.setAppletSecuredState();
        break;

      default:
        ISOException.throwIt(Constants.SW_PUT_DATA_OP_INVALID_VALUE);
        return;
      }

      // If this is a bulk operation,
    } while (isBulk && !reader.isEOF());

    // Done, no response data required
    pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
  }

  /**
   * This method is the equivalent of the CHANGE REFERENCE DATA command, however it is intended to
   * operate on key references that are NOT listed in SP800-37-4. This is the primary method by
   * which administrative key references are updated and is intended to fill in the gap in PIV that
   * does not cover how pre-personalisation is implemented.
   *
   * @param id        The target key / pin reference being changed
   * @param mechanism The target key mechanism (FF if a pin reference)
   * @param buffer    The incoming APDU buffer
   * @param offset    The starting offset of the CDATA section
   * @param length    The length of the CDATA section
   *                  <p>
   *                  The main differences to CHANGE REFERENCE DATA are: - It supports updating any
   *                  key reference that is not covered by CHANGE REFERENCE DATA already - It
   *                  requires a global platform secure channel to be operating with the CEncDec
   *                  attribute (encrypted) - It does NOT require the old value to be supplied in
   *                  order to change a key - It also supports updating the PIN/PUK values, without
   *                  requiring knowledge of the old value
   */
  void changeReferenceDataAdmin(byte id, byte mechanism, PIVAPDU pApdu) throws ISOException {

    final byte CONST_TAG_SEQUENCE = (byte) 0x30;

    // The PIV Card Application may allow the reference data associated with other
    // key references
    // to be changed by the PIV Card Application CHANGE REFERENCE DATA, if PIV Card
    // Application will
    // only perform the command with other key references if the requirements
    // specified in Section
    // 2.9.2 of FIPS 201-2 are satisfied.

    //
    // SECURITY PRE-CONDITION
    //

    // Check operator integrity
    operator.performIntegrityCheck();

    // The command must have been sent over an administrative channel
    if (pApdu.getSecureChannel() != PIVAPDU.SECURE_CHANNEL_SCP || !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    if (PIVVerifier.isVerifierId(id)) {
      //
      // CASE 1 - Updating a Verifier value
      //

      PIVVerifier verifier = dataStore.getVerifier(id);
      if (verifier == null) {
        ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
      }

      // Update the PIN (the format is verified internally)
      verifier.update(buffer, offset, length);
    } else {
      //
      // CASE 2 - Updating a cryptographic key element
      //

      // PRE-CONDITION 1 - The key reference and mechanism MUST point to an existing
      // key
      PIVKey key = dataStore.getKey(id, mechanism);
      if (key == null) {
        // If any key reference value is specified that is not supported by the card,
        // the PIV Card
        // Application shall return the status word '6A 88'.
        ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
      }

      // PRE-CONDITION 2 - The key object MUST have the ATTR_IMPORTABLE attribute
      if (!key.hasAttribute(PIVKey.ATTR_IMPORTABLE)) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }

      // Set up our TLV reader
      TLVReader reader = TLVReader.getInstance(buffer, offset, length);

      //
      // LEGACY: The inclusion of the parent SEQUENCE tag is now only optional and
      // considered
      // legacy functionality.
      //
      if (reader.match(CONST_TAG_SEQUENCE)) {
        // Move to the child tag
        reader.moveInto();
      }

      //
      // EXECUTION STEPS
      //

      // STEP 1 - Update the relevant key element
      key.update(reader.getTag(), buffer, reader.getDataOffset(), reader.getLength());
    }

    // Done, no response data required
    pApdu.setOutgoingStatus(ISO7816.SW_NO_ERROR);
  }

  private short processGetVersion(TLVWriter writer) {

    final byte CONST_TAG_APPLICATION = (byte) 0x80;
    final byte CONST_TAG_MAJOR = (byte) 0x81;
    final byte CONST_TAG_MINOR = (byte) 0x82;
    final byte CONST_TAG_REVISION = (byte) 0x83;
    final byte CONST_TAG_DEBUG = (byte) 0x84;

    // Application
    writer.write(CONST_TAG_APPLICATION, Platform.getPlatformLabel(), (short) 0, Platform.getPlatformLabelLength());

    // Major
    writer.write(CONST_TAG_MAJOR, Config.VERSION_MAJOR);

    // Minor
    writer.write(CONST_TAG_MINOR, Config.VERSION_MINOR);

    // Revision
    writer.write(CONST_TAG_REVISION, Config.VERSION_REVISION);

    // Debug
    writer.write(CONST_TAG_DEBUG, Config.VERSION_DEBUG ? TLV.TRUE : TLV.FALSE);

    return writer.finish();
  }

  private short processGetStatus(TLVWriter writer) {

    final byte CONST_TAG_APPLET_STATE = (byte) 0x80;
    final byte CONST_TAG_OP_ROLE = (byte) 0x81;
    final byte CONST_TAG_OP_ID = (byte) 0x82;
    final byte CONST_TAG_OP_IMMEDIATE = (byte) 0x83;
    final byte CONST_TAG_SM_STATE = (byte) 0x84;
    final byte CONST_TAG_VCI_STATE = (byte) 0x85;
    final byte CONST_TAG_CONTACTLESS = (byte) 0x86;
    final byte CONST_TAG_FIPS_MODE = (byte) 0x87;

    // We don't check the operator integrity here since it serves to security function

    // Applet State
    writer.write(CONST_TAG_APPLET_STATE, GPSystem.getCardContentState());

    // PIN Verified
    writer.write(CONST_TAG_OP_ROLE, operator.getRoles());

    // PIN Verified
    writer.write(CONST_TAG_OP_ID, operator.getId());

    // PIN Always
    writer.write(CONST_TAG_OP_IMMEDIATE, operator.getImmediateFlag(false) ? TLV.TRUE : TLV.FALSE);

    // SM & VCI State
    // NOTE: This does NOT indicate whether the current command is PIV-SM wrapped, or VCI.
    // Instead it just indicates if these are established and therefore CAN be used.
    if (channelPIVSM.isEstablished()) {
      PIVVerifier pc = dataStore.getVerifier(Constants.ID_AUTH_PAIRING_CODE);
      boolean vci = (pc == null || pc.isValidated());

      writer.write(CONST_TAG_SM_STATE, TLV.TRUE);
      writer.write(CONST_TAG_VCI_STATE, vci ? TLV.TRUE : TLV.FALSE);
    } else {
      writer.write(CONST_TAG_SM_STATE, TLV.FALSE);
      writer.write(CONST_TAG_VCI_STATE, TLV.FALSE);
    }

    // Contactless
    writer.write(CONST_TAG_CONTACTLESS, Platform.isContactless() ? TLV.TRUE : TLV.FALSE);

    // FIPS Mode
    writer.write(CONST_TAG_FIPS_MODE, Config.FIPS_APPROVED_MODE ? TLV.TRUE : TLV.FALSE);

    return writer.finish();
  }

  private short processGetRandom(byte length, TLVWriter writer) {
    if (config.readFlag(Config.CONFIG_RESTRICT_GET_RANDOM) && !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    // Generate this tag manually
    final byte TAG_RANDOM = (byte) 0x80;
    writer.writeTagByte(TAG_RANDOM);
    writer.writeLength(length);
    short offset = writer.getOffset();
    offset = Platform.Cryptography.generateRandom(writer.getBuffer(), offset, length);
    writer.setOffset(offset);
    return writer.finish();
  }

  private short processGetConfig(TLVWriter writer) {
    if (config.readFlag(Config.CONFIG_RESTRICT_ENUMERATION) && !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    return config.getConfig(writer);
  }

  private short processGetContainer(byte index, TLVWriter writer) {
    if (config.readFlag(Config.CONFIG_RESTRICT_ENUMERATION) && !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    PIVObject object = dataStore.getContainerByIndex(index);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return 0;
    }

    return object.getHeader(writer);
  }

  private short processGetKey(byte index, TLVWriter writer) {
    if (config.readFlag(Config.CONFIG_RESTRICT_ENUMERATION) && !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    PIVObject object = dataStore.getKeyByIndex(index);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return 0;
    }

    return object.getHeader(writer);
  }

  private short processGetVerifier(byte index, TLVWriter writer) {
    if (config.readFlag(Config.CONFIG_RESTRICT_ENUMERATION) && !operator.hasRole(Operator.ROLE_ADMIN)) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    PIVObject object = dataStore.getVerifierByIndex(index);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return 0;
    }

    return object.getHeader(writer);
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming PIV Buffer
   * @return The length of the entire data object to be returned
   */
  void getDataExtended(PIVAPDU pApdu) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final short CONST_LEN = (short) 3;
    final byte CONST_TAG_EXTENDED = (byte) 0x2F;

    final byte CONST_TAG_DATA = (byte) 0x53;

    final short CONST_DO_GET_VERSION = (short) 0x4756; // GV
    final short CONST_DO_GET_STATUS = (short) 0x4753; // GS
    final short CONST_DO_GET_RANDOM = (short) 0x4752; // GR
    final short CONST_DO_GET_CONFIG = (short) 0x4743; // GC
    final short CONST_DO_GET_DATA_OBJECT = (short) 0x4744; // GD
    final short CONST_DO_GET_KEY = (short) 0x474B; // GK
    final short CONST_DO_GET_PIN = (short) 0x4750; // GP

    byte[] buffer = pApdu.getData();
    short offset = pApdu.getDataOffset();
    short length = pApdu.getDataLength();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The length must be between 3 and 5 bytes
    // NOTE: Format is [5C] [L:1] [T:1-3]
    if (length < 3 || length > 5) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Copy the APDU buffer to the scratch buffer so that we can reference it with
    // our TLVReader
    TLVReader reader = TLVReader.getInstance(buffer, offset, length);

    // PRE-CONDITION 2 - The 'TAG' data element must be present
    if (!reader.match(CONST_TAG)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 3 - The 'TAG' data element must be the correct length
    if (reader.getLength() != CONST_LEN) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // PRE-CONDITION 4 - The 'TAG' value must start with CONST_TAG_EXTENDED
    if (!reader.matchData(CONST_TAG_EXTENDED)) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // Retrieve the 2-byte extended data identifier
    short idOffset = reader.getDataOffset();
    idOffset++; // Move to the 2nd data byte
    short id = Util.getShort(buffer, idOffset);

    //
    // EXECUTION
    //
    // NOTE:
    // An assumption is made here that all responses can fit within a short length
    // TLV object so we put a sanity check at the end to make sure this is the case.
    //

    // STEP 1 - Call the appropriate handler
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(buffer, Constants.ZERO_SHORT, TLV.LENGTH_1BYTE_MAX, CONST_TAG_DATA);
    short outLength = 0;

    switch (id) {
    case CONST_DO_GET_VERSION:
      outLength = processGetVersion(writer);
      break;

    case CONST_DO_GET_STATUS:
      outLength = processGetStatus(writer);
      break;

    case CONST_DO_GET_RANDOM:
      outLength = processGetRandom(pApdu.getP2(), writer);
      break;

    case CONST_DO_GET_CONFIG:
      outLength = processGetConfig(writer);
      break;

    case CONST_DO_GET_DATA_OBJECT:
      outLength = processGetContainer(pApdu.getP2(), writer);
      break;

    case CONST_DO_GET_KEY:
      outLength = processGetKey(pApdu.getP2(), writer);
      break;

    case CONST_DO_GET_PIN:
      outLength = processGetVerifier(pApdu.getP2(), writer);
      break;

    default:
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // Length sanity check (I should never construct a length larger than a short
    // length)
    if (outLength > TLV.LENGTH_1BYTE_MAX) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Set up the outgoing buffer
    pApdu.setOutgoingAPDU(Constants.ZERO_SHORT, outLength);
  }

  private boolean isVirtualContactInterface(PIVAPDU pApdu) {

    boolean result = true;

    //
    // According to SP800-73, the Virtual Contact Interface is established when ALL the following
    // conditions are met:
    //

    // 1. The command is submitted over secure messaging, AND
    if (pApdu.getSecureChannel() != PIVAPDU.SECURE_CHANNEL_PIVSM) {
      result = false;
    }

    // 2. The Discovery Object is present, AND
    // N/A - The discovery object always exists in OpenFIPS201

    // 3. Bit 4 of the first byte of the PIN Usage Policy is one, AND
    // N/A - If a secure messaging channel was set, this will always be true

    // 4. The security status indicator associated with the pairing code is TRUE
    //    OR Bit 3 of the first byte of the PIN Usage Policy is one
    // NOTE:
    // - If the pairing code is not present, it is not required for VCI
    // - If the pairing code is present, it is always required for VCI
    PIVVerifier pairingCode = dataStore.getVerifier(Constants.ID_AUTH_PAIRING_CODE);
    if (pairingCode != null && !pairingCode.isValidated()) {
      result = false;
    }

    return result;
  }

  /**
   * Validates the current security conditions for managing/writing a specified object.
   *
   * @param object The object to check permissions for
   * @return True of the access mode check passed
   */
  private void checkWritePrivilege(PIVObject object, PIVAPDU pApdu) {

    boolean result = false;

    // Select the appropriate access mode to check
    byte mode = !Platform.isContactless() || isVirtualContactInterface(pApdu) ? object.getModeContact()
        : object.getModeContactless();

    // Always perform an integrity check on the operator permissions before using them
    operator.performIntegrityCheck();

    //
    // ACCESS CONDITION 1 - The 'Applet Administrator' role is authenticated
    // NOTE: This only pass if BOTH the following conditions are met:
    // 1) The operator role is AUTH_ROLE_ADMIN
    // 2) The APDU that initiated this check was wrapped by the SCP
    //
    if (operator.hasRole(Operator.ROLE_ADMIN) && pApdu.getSecureChannel() == PIVAPDU.SECURE_CHANNEL_SCP) {
      result = true;
    }

    //
    // ACCESS CONDITION 2 - The 'Key Holder' role is authenticated and the
    // authenticated key matches the object's administrative key.
    //
    else if (operator.hasRole(Operator.ROLE_KEY_HOLDER) && object.getAdminKey() == operator.getId()) {
      result = true;
    }

    //
    // ACCESS CONDITION 3 - The object permits management by the 'User' role
    else if (((mode & PIVObject.ACCESS_MODE_ALWAYS) != PIVObject.ACCESS_MODE_ALWAYS)
        && ((mode & PIVObject.ACCESS_MODE_USER_ADMIN) == PIVObject.ACCESS_MODE_USER_ADMIN)) {
      // NOTE: A failure here will cause the same error as the final check in this method
      checkAccessPrivilege(object, pApdu);
      result = true;
    }

    if (!result) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // The access check passed
  }

  /**
   * Validates the current security conditions for access to a given data or key object
   *
   * @param object The object to check permissions for
   * @return True of the access mode check passed
   */
  private void checkAccessPrivilege(PIVObject object, PIVAPDU pApdu) {
    boolean result = false;

    // Select the appropriate access mode to check    
    byte mode = !Platform.isContactless() || isVirtualContactInterface(pApdu) ? object.getModeContact()
        : object.getModeContactless();

    // Always perform an integrity check on the operator permissions before using them
    operator.performIntegrityCheck();

    // Get the IMMEDIATE state and then clear it immediately
    boolean immediate = operator.getImmediateFlag(true);

    //
    // SPECIAL CONDITION 1 - The 'Applet Administrator' role is authenticated
    // NOTE: This only passes if BOTH the following conditions are met:
    // 1) The operator role is AUTH_ROLE_ADMIN
    // 2) The APDU that initiated this check was wrapped by the SCP
    //
    if (operator.hasRole(Operator.ROLE_ADMIN) && pApdu.getSecureChannel() == PIVAPDU.SECURE_CHANNEL_SCP) {
      // If the above conditions are met, no negative checks are considered (i.e. PIN_ALWAYS or SM)
      return;
    }

    // ACCESS CONDITION 1 - Check for special ALWAYS condition, which ignores PIN_ALWAYS
    if ((mode & PIVObject.ACCESS_MODE_ALWAYS) == PIVObject.ACCESS_MODE_ALWAYS) {
      result = true;
    } else {
      // ACCESS CONDITION 2 - The 'Key Holder' role is authenticated and the authenticated key 
      // matches the object's administrative key.
      if (operator.hasRole(Operator.ROLE_KEY_HOLDER) && object.getAdminKey() == operator.getId()) {
        result = true;
      }
      // ACCESS CONDITION 4 - An authenticated user may access with MODE_PIN_ALWAYS if
      // there was an immediately preceding authentication
      // NOTE:
      // PIN Always is checked later because it is applied to 
      else if ((mode & PIVObject.ACCESS_MODE_PIN) == PIVObject.ACCESS_MODE_PIN) {
        result = (operator.hasRole(Operator.ROLE_USER));
      }

      // SPECIAL - 'IMMEDIATE' CHECK (Previously called 'PIN ALWAYS')
      // 
      // This check is independent and so result can be reset to false if this fails.
      // If the object has the IMMEDIATE attribute and this is not ROLE_ADMIN, it must
      // pass the IMMEDIATE check.
      //
      // NOTE: It doesn't make a lot of sense to apply this to the KEY_HOLDER, but the PIV
      // test runner will fail if we don't contrain them as well.
      if ((mode & PIVObject.ACCESS_MODE_IMMEDIATE) == PIVObject.ACCESS_MODE_IMMEDIATE) {
        result = immediate;
      }
    }

    //
    // SPECIAL - SECURE MESSAGING CHECK
    //
    // This check is independent and so result can be reset to false if this fails.
    // It requires that PIV Secure Messaging was used, but it will skip the check if
    // SCP was used as this only possible for an administrative connection, which is protected.
    if ((mode & PIVObject.ACCESS_MODE_SM) == PIVObject.ACCESS_MODE_SM
        && pApdu.getSecureChannel() == PIVAPDU.SECURE_CHANNEL_NONE) {
      result = false;
    }

    if (!result) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // The access check passed
  }

  private short buildDiscoveryObject(byte[] buffer, short offset) {

    short length = (short) Config.TEMPLATE_DISCOVERY.length;

    // Retrieve the VCI / SM configuration
    // NOTE: Although OpenFIPS201 is flexible and you could define an SM key with any identifier,
    // this Discovery Object is specifically a PIV compliance issue and so we look specifically for
    // the default key identifier.
    boolean vci = dataStore.getKey(Config.DEFAULT_PIVSM_KEY) != null;
    boolean pairingCode = dataStore.getVerifier(Constants.ID_AUTH_PAIRING_CODE) != null;
    boolean localPin = dataStore.getVerifier(Constants.ID_AUTH_LOCAL_PIN) != null;
    boolean globalPin = dataStore.getVerifier(Constants.ID_AUTH_GLOBAL_PIN) != null;

    // Write the template
    offset = Util.arrayCopyNonAtomic(Config.TEMPLATE_DISCOVERY, Constants.ZERO_SHORT, buffer, offset, length);

    // Move the offset back by 2 so we can write our policy bytes
    offset -= (byte) 2;

    // Tag 0x5F2F encodes the PIN Usage Policy in two bytes:
    // FIRST BYTE
    // -----------------------------
    buffer[offset++] = (byte)
    // Bit 8 of the first byte shall be set to zero

    // Bit 7 is set to 1 to indicate that the mandatory PIV Card Application PIN
    // satisfies the PIV Access Control Rules (ACRs) for command execution and data object access.
    ((localPin ? (byte) (1 << 6) : (byte) 0)

        // Bit 6 indicates whether the optional Global PIN satisfies the PIV ACRs for
        // command execution and PIV data object access.
        | (globalPin ? (byte) (1 << 5) : (byte) 0)

        // Bit 5 indicates whether the optional OCC satisfies the PIV ACRs for
        // command execution and PIV data object access
        // | (config.readFlag(Config.CONFIG_OCC_MODE) ? (byte) (1 << 4) : (byte) 0)

        // Bit 4 indicates whether the optional VCI is implemented
        | (vci ? (byte) (1 << 3) : (byte) 0)

        // Bit 3 is set to zero if the pairing code is required to establish a VCI and
        // is set to one if a VCI is established without pairing code
        | (vci && pairingCode ? (byte) 0 : (byte) (1 << 2))

    //  Bits 2 and 1 of the first byte shall be set to zero
    );

    // SECOND BYTE
    // -----------------------------
    // The second byte of the PIN Usage Policy encodes the cardholder's PIN preference for PIV Cards 
    // with both the PIV Card Application PIN and the  Global PIN enabled:

    // 0x10 indicates that the PIV Card Application PIN is the primary PIN used
    // to satisfy the PIV ACRs for command execution and object access.
    // 0x20 indicates that the Global PIN is the primary PIN used to satisfy the
    // PIV ACRs for command execution and object access.

    // IMPLEMENTATION NOTE:
    // We infer this from which PIN was added first to the data store
    buffer[offset] = (dataStore.isGlobalPinPreferred() ? (byte) 0x20 : (byte) 0x10);
    return length;
  }
}
