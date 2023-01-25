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
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * The main applet class, which is responsible for handling APDU's and dispatching them to the PIV
 * provider.
 */
public final class OpenFIPS201 extends Applet implements AppletEvent {
  /*
   * PERSISTENT applet variables (EEPROM)
   */

  // GlobalPlatform instructions for establishing a Secure Channel
  private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
  private static final byte INS_GP_EXTERNAL_AUTHENTICATE = (byte) 0x82;
  private static final byte INS_GP_GET_RESPONSE = (byte) 0xC0;
  /*
   * Applet Commands - PIV STANDARD
   */
  private static final byte INS_PIV_SELECT = (byte) 0xA4;

  /*
   * Applet Commands - Administrative
   */
  private static final byte INS_PIV_GET_DATA = (byte) 0xCB;
  private static final byte INS_PIV_VERIFY = (byte) 0x20;
  private static final byte INS_PIV_CHANGE_REFERENCE_DATA = (byte) 0x24;
  private static final byte INS_PIV_RESET_RETRY_COUNTER = (byte) 0x2C;
  private static final byte INS_PIV_GENERAL_AUTHENTICATE = (byte) 0x87;
  private static final byte INS_PIV_PUT_DATA = (byte) 0xDB;
  private static final byte INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;
  // Helper constants
  private static final short ZERO_SHORT = (short) 0;
  private static final byte SC_MASK =
      SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC;
  private final PIV piv;

  //
  // Persistent state definitions
  //

  public OpenFIPS201() {

    // Create our PIV provider
    piv = new PIV();
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new OpenFIPS201().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  @Override
  public boolean select() {
    //
    // If we are not permitted to use the applet over contactless, fail at selection.
    // This means that the rest of the applet can happily assume we are permitted.
    //
    byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
    boolean contactless =
        (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A)
            || (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);

    // Update the interface
    piv.setIsContactless(contactless);

    // Check if we are permitted to be selected over the current interface. If not, decline to be
    // selected, which means the only way to recover this is to be used over a contact interface.
    return piv.isInterfacePermitted();
  }

  @Override
  public void deselect() {

    // Reset any security domain session (see resetSecurity() documentation)
    SecureChannel secureChannel = GPSystem.getSecureChannel();
    secureChannel.resetSecurity();

    //
    // The PIV applet specification defines rules for how to manage security conditions when
    // it is selected or deselected. These rules/requirements are described in SP800-73-4

    // Part 2 - 3.1.1 - SELECT Card Command, and can be simplified as follows:
    // 		a.	If the PIV applet is not selected and becomes selected, the security
    //			conditions must be reset.
    //		b.	If the PIV applet is selected and becomes not selected (i.e. a different
    //			applet is selected), then the PIV applet becomes selected again, the security
    //			conditions must be reset.
    //		c.	If the PIV applet is selected and a select command is issued again for the
    //			PIV applet (i.e. it is re-selected), then the security conditions must not be
    //			reset.
    //		d.	If the PIV applet is selected and a select command is issued for a non-existent
    //			applet, then the PIV applet should remain selected and the security conditions
    //			must not be reset.

    // Reset the PIV security status only if we are not reselecting the current applet
    if (!reSelectingApplet()) {
      piv.deselect();
    }
  }

  @Override
  public void uninstall() {
  	//
  	// NOTE:
  	// - Get rid of all static instances that would prevent GP from deleting the applet instance 
  	//   without also deleting the corresponding package
  	// - TODO: Change TLVReader and TLVWriter to an instance
    TLVReader.terminate();
    TLVWriter.terminate();
    PIVCrypto.terminate();
  }

  @Override
  public void process(APDU apdu) {

    //
    // Handle incoming APDUs
    //

    final byte[] buffer = apdu.getBuffer();

    if (selectingApplet()) {
      processPIV_SELECT(apdu);
      return;
    }

    // SPECIAL CASE 1 - GET RESPONSE
    // We handle the GET RESPONSE command differently because it is the only ISO 7816 Case 1 / 3
    // command this applet supports and we don't care about secure channel processing.
    if (buffer[ISO7816.OFFSET_INS] == INS_GP_GET_RESPONSE) {
      piv.processOutgoing(apdu);
      return;
    }
    // TODO: Decide if this should go back to being called every time
    // The implication is that if a caller does this:
    // - GET DATA (big object)
    // - SOME OTHER COMMAND
    // - GET RESPONSE
    // ... in some cases it will continue the original GET DATA.

    //
    // We can now safely call setIncomingAndReceive because all other expected commands are
    // either CASE 2 or 4 (command data present).
    //
    short length = apdu.setIncomingAndReceive();

    //
    // Process GlobalPlatform Secure Channel unwrapping if relevant to this command
    // NOTE:
    // We only consider the channel to be secure if ALL these conditions are true:
    // 1) We have a previously established secure channel
    // 2) The applet has not been deselected
    // 3) The current command indicates it is transmitting a SCP protected command
    // 4) The command unwrap method successfully completed

    // Always default to false for secure channel until proven otherwise
    piv.setIsSecureChannel(false);

    if (apdu.isSecureMessagingCLA()) {
      SecureChannel secureChannel = GPSystem.getSecureChannel();
      if ((secureChannel.getSecurityLevel() & SC_MASK) == SC_MASK) {
        // Validate and unwrap the APDU, including the header bytes
        length += ISO7816.OFFSET_CDATA; // Add the header length
        length = secureChannel.unwrap(buffer, (short) 0, length);
        length -= ISO7816.OFFSET_CDATA; // Remove the header length
        piv.setIsSecureChannel(true);
      }
    }

    //
    // Process any outstanding chain requests
    //
    // NOTES:
    // - If there is an outstanding chain request to process, this method will throw an ISOException
    //	 (including SW_NO_ERROR) and no further processing will occur.
    // - It is important that this command is handled before any GP SCP authentication is called to
    //   prevent a downgrade attack where the attacker waits for a sensitive large-command to be
    //   executed and then intercepts the session and cancels the secure channel (thus removing
    //   session encryption).
    // - TODO: Make sure that if we are supposed to be receiving this data under SCP, that it is
    //   	   definitely still set.

    // We pass the byte array, offset and length here because the previous call to unwrap() may have
    // altered the length
    piv.processIncomingObject(buffer, apdu.getOffsetCdata(), length);

    //
    // Normal APDU processing
    //
    // TODO: Re-introduce CLA checking

    switch (buffer[ISO7816.OFFSET_INS]) {
      case INS_GP_INITIALIZE_UPDATE: // Case 4
        processGP_SECURECHANNEL(apdu, true);
        break;

      case INS_GP_EXTERNAL_AUTHENTICATE: // Case 4
        processGP_SECURECHANNEL(apdu, false);
        break;

        // Application Commands
      case INS_PIV_SELECT: // Case 4
        processPIV_SELECT(apdu);
        break;

      case INS_PIV_GET_DATA: // Case 4
        processPIV_GET_DATA(apdu);
        break;

      case INS_PIV_VERIFY: // Case 2
        processPIV_VERIFY(apdu);
        break;

      case INS_PIV_CHANGE_REFERENCE_DATA: // Case 2
        processPIV_CHANGE_REFERENCE_DATA(apdu);
        break;

      case INS_PIV_RESET_RETRY_COUNTER: // Case 2
        processPIV_RESET_RETRY_COUNTER(apdu);
        break;

      case INS_PIV_GENERAL_AUTHENTICATE: // Case 4
        processPIV_GENERAL_AUTHENTICATE(apdu);
        break;

      case INS_PIV_PUT_DATA: // Case 2
        processPIV_PUT_DATA(apdu);
        break;

      case INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR: // Case 2
        processPIV_GENERATE_ASYMMETRIC_KEYPAIR(apdu);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  /**
   * Processes the GlobalPlatform Secure Channel Protocol (SCP) authentication mechanisms
   *
   * @param apdu The APDU to process.
   * @param reset If true, reset the secure channel
   */
  private void processGP_SECURECHANNEL(APDU apdu, boolean reset) {

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - Secure Channel access must be permitted on the current interface
    if (!piv.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /*
     * EXECUTION STEPS
     */

    SecureChannel secureChannel = GPSystem.getSecureChannel();

    if (reset) {
      secureChannel.resetSecurity();
    }

    // STEP 1 - Call the PIV 'SELECT' command
    short length = secureChannel.processSecurity(apdu);

    // Send the response
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
  }

  /**
   * Process the PIV 'SELECT' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_SELECT(APDU apdu) {

    byte[] buffer = apdu.getBuffer();
    short ne = apdu.setOutgoing();

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - This must be called only when the applet is selected or re-selected
    if (!selectingApplet()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV 'SELECT' command in all cases to handle the PIV SELECT rules
    short length = piv.select(buffer, (short) 0);

    // STEP 2 - Check the ne value
    if (ne < length) {
      // Caller requested less data than the length.  Return as much as caller requested.
      length = ne;
    }

    // Step 3 - Return data from select command
    apdu.setOutgoingLength(length);
    apdu.sendBytes((short) 0, length);
  }

  /**
   * Process the PIV 'GET DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GET_DATA(APDU apdu) {

    final byte P1 = (byte) 0x3F;
    final byte P2 = (byte) 0xFF;
    final byte P2_EXTENDED = (byte) 0x00;

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant '3F'
    if (buffer[ISO7816.OFFSET_P1] != P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 2 - The P2 value must be equal to the constant 'FF'
    boolean extended = false;
    if (buffer[ISO7816.OFFSET_P2] == P2_EXTENDED) {
      extended = true;
    } else if (buffer[ISO7816.OFFSET_P2] != P2) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV 'GET DATA' command
    if (extended) {
      piv.getDataExtended(buffer, ISO7816.OFFSET_CDATA, length);
    } else {
      piv.getData(buffer, ISO7816.OFFSET_CDATA);
    }

    // NOTE: If no exception occurred during processing, the ChainBuffer now contains a reference
    //		 to a data object to write to the client.

    // STEP 2 - Process the first frame of the chainBuffer for this response
    piv.processOutgoing(apdu);
  }

  /**
   * Processes the PIV 'PUT DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_PUT_DATA(APDU apdu) {

    final byte CONST_P1 = (byte) 0x3F;
    final byte CONST_P2 = (byte) 0xFF;
    final byte CONST_P2_ADMIN = (byte) 0x00;

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - Administrative access must be permitted on the current interface
    if (!piv.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 3 - The P2 value must be equal to the constant CONST_P2 or CONST_P2_ADMIN
    boolean admin = false;

    if (buffer[ISO7816.OFFSET_P2] == CONST_P2_ADMIN) {
      // This is an administrative command
      admin = true;
    } else if (buffer[ISO7816.OFFSET_P2] != CONST_P2) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the applicable PIV 'PUT DATA' command
    if (admin) {
      piv.putDataAdmin(buffer, ISO7816.OFFSET_CDATA, length);
    } else {
      piv.putData(buffer, ISO7816.OFFSET_CDATA, length);
    }
  }

  /**
   * Process the PIV 'VERIFY' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_VERIFY(APDU apdu) {

    final byte CONST_P1_AUTH = (byte) 0x00;
    final byte CONST_P1_RESET = (byte) 0xFF;

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1_AUTH or CONST_P1_RESET
    // PRE-CONDITION 2 - If the P1 value is set to CONST_P1_RESET, the data field must be absent
    // NOTE: This is handled by the cases below

    // PRE-CONDITION 3 - If the P1 value is set to CONST_P1_AUTH and the data field is present, the
    //					 length must be equal to CONST_LC
    // NOTE: This is handled inside the PIVProvider

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the appropriate PIV 'Verify' command

    // CASE 1 - If P1='00', and Lc and the command data field are absent, the command can be
    // 			used to retrieve the number of further retries allowed ('63 CX'), or to check whether
    // 			verification is not needed ('90 00').
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_AUTH && length == ZERO_SHORT) {
      // Retrieve the authentication status using the key reference supplied in P2
      piv.verifyGetStatus(buffer[ISO7816.OFFSET_P2]);
      return;
    }

    // CASE 2 - If P1='FF', and Lc and the command data field are absent, the command shall reset
    // 			the security status of the key reference in P2.
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_RESET && length == ZERO_SHORT) {
      // Reset the authentication status using the key reference supplied in P2
      piv.verifyResetStatus(buffer[ISO7816.OFFSET_P2]);
      return;
    }

    // CASE 3 - If P1='00', and Lc and the command data field are present, then the authentication
    //          data in the command data field shall be compared against the reference data
    //          associated with the key reference [...]
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_AUTH && length != ZERO_SHORT) {
      // Verify using the key reference supplied in P2
      piv.verify(buffer[ISO7816.OFFSET_P2], buffer, ISO7816.OFFSET_CDATA, length);
      return;
    }

    // If we reached here, then none of the cases applied
    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
  }

  /**
   * Process the PIV 'CHANGE REFERENCE DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_CHANGE_REFERENCE_DATA(APDU apdu) {

    final byte CONST_P1 = (byte) 0x00;
    final byte CONST_P1_ADMIN = (byte) 0xFF;

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P2 value must be set to one of the standard PIN references
    // Either: '00' (Global PIN), '80' (PIV APP PIN) or '81' (PUK)
    boolean isStandard =
        (buffer[ISO7816.OFFSET_P2] == PIV.ID_CVM_GLOBAL_PIN
            || buffer[ISO7816.OFFSET_P2] == PIV.ID_CVM_LOCAL_PIN
            || buffer[ISO7816.OFFSET_P2] == PIV.ID_CVM_PUK);

    // PRE-CONDITION 2 - If the P2 value is set to one of the standard PIN references but the P1
    // value is set to CONST_P1_ADMIN, we consider this an administrative command for the purposes
    // of changing the PINs over SCP
    if (isStandard && buffer[ISO7816.OFFSET_P1] == CONST_P1_ADMIN) {
      isStandard = false;
    }

    // PRE-CONDITION 3 - If the P2 value is set to one of the standard PIN references, the P1 value
    // must be equal to the constant CONST_P1
    if (isStandard && buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the appropriate method
    if (isStandard) {
      // CASE 1 - If the value of P2 is one of our standard PIN references, we handle this according
      // the SP800-73-4
      piv.changeReferenceData(buffer[ISO7816.OFFSET_P2], buffer, ISO7816.OFFSET_CDATA, length);
    } else {
      // CASE 2 - Otherwise, we pass it to the administrative command handler
      piv.changeReferenceDataAdmin(buffer[ISO7816.OFFSET_P2], buffer, ISO7816.OFFSET_CDATA, length);
    }
  }

  /**
   * Process the PIV 'RESET RETRY COUNTER' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_RESET_RETRY_COUNTER(APDU apdu) {

    final byte CONST_P1 = (byte) 0x00;
    final byte CONST_LC = (byte) 0x10;

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 2 - The LC (length) value must be equal to the constant CONST_LC
    if (length != CONST_LC) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    /*
     * EXECUTION STEPS
     */

    piv.resetRetryCounter(buffer[ISO7816.OFFSET_P2], buffer, ISO7816.OFFSET_CDATA, length);
  }

  /**
   * Process the PIV 'GENERAL AUTHENTICATE' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GENERAL_AUTHENTICATE(APDU apdu) {

    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

    /*
     * PRE-CONDITIONS
     */

    // NONE

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV GENERAL AUTHENTICATE method
    length = piv.generalAuthenticate(buffer, ISO7816.OFFSET_CDATA, length);

    // STEP 2 - Process the first frame of the chainBuffer for this response, if any
    if (length > 0) piv.processOutgoing(apdu);
  }

  /**
   * Process the PIV 'GENERATE ASYMMETRIC KEYPAIR' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GENERATE_ASYMMETRIC_KEYPAIR(APDU apdu) {

    final byte CONST_P1 = (byte) 0x00;

    byte[] buffer = apdu.getBuffer();

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - Administrative access must be permitted on the current interface
    if (!piv.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 3 - The P2 value must be set to one of '04', '9A', '9C', '9D', '9E'
    // NOTE: This is ignored because we use a flexible key system internally

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV GENERATE ASYMMETRIC KEY command
    piv.generateAsymmetricKeyPair(buffer, ISO7816.OFFSET_CDATA);

    // STEP 2 - Process the first frame of the chainBuffer for this response
    piv.processOutgoing(apdu);
  }
}
