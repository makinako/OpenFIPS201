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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * The main applet class, which is responsible for handling APDU's and dispatching them to the PIV
 * provider.
 */
public final class OpenFIPS201 extends Applet implements AppletEvent {

  ////////////////////////////////////////////////////////////////////////////////
  // Applet Constants
  ////////////////////////////////////////////////////////////////////////////////

  // 
  // ISO Inter-Industry INS Values (PIV)
  //
  static final byte INS_ISO7816_GET_RESPONSE = (byte) 0xC0;
  static final byte INS_PIV_SELECT = (byte) 0xA4;
  static final byte INS_PIV_GET_DATA = (byte) 0xCB;
  static final byte INS_PIV_VERIFY = (byte) 0x20;
  static final byte INS_PIV_CHANGE_REFERENCE_DATA = (byte) 0x24;
  static final byte INS_PIV_RESET_RETRY_COUNTER = (byte) 0x2C;
  static final byte INS_PIV_GENERAL_AUTHENTICATE = (byte) 0x87;
  static final byte INS_PIV_PUT_DATA = (byte) 0xDB;
  static final byte INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;

  // 
  // Proprietary INS Values
  //
  static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
  static final byte INS_GP_EXTERNAL_AUTHENTICATE = (byte) 0x82;
  static final byte INS_DEBUG_RUN_ACVP_KDF = (byte) 0x80E0;
  static final byte INS_DEBUG_RUN_ACVP_KC = (byte) 0x80E1;

  // Indicates that the Application state (GP Card Content) is set to
  // SECURED, preventing pre-personalisation.
  static final byte APPLICATION_SECURED = (byte) 0x0F;

  // PERSISTENT - PIV application provider
  private final PIV piv;

  // PERSISTENT - PIV APDU buffer and Secure Channel providers
  private final PIVAPDU pApdu;
  private final ChannelSCP channelSCP;

  // TRANSIENT - Applet error state (used to track CAST failure)
  private final byte[] errorState;

  private static final byte ERROR_STATE_CAST_FAILURE = (byte) 0xFF;

  @SuppressWarnings("unused")
  public OpenFIPS201() {

    //
    // !!! CODE SAFETY GUARDS !!!
    // NOTE: If test code is present/enabled in the code, the VERSION_DEBUG flag must be also set
    // to notify users that this is not a production-capable build.
    //

    // NOTE: We safely ignore the static analyser issue here
    if (!Config.VERSION_DEBUG
        && (Config.DEBUG_FIPS_RUN_ACVP || Config.DEBUG_FIPS_FAIL_CAST || Config.DEBUG_FIXED_RANDOM)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    Platform.init();

    channelSCP = new ChannelSCP();
    piv = new PIV();
    pApdu = new PIVAPDU(channelSCP, piv.getSecureMessaging());
    errorState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
    errorState[0] = Constants.ZERO_BYTE;
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) { // NO_UCD
    new OpenFIPS201().register(bArray, (short) (bOffset + 1), bArray[bOffset]);

    // Some platforms, including the P71D600, do not automatically delete temporary objects created
    // during installation. This explicitly requests deletion of these.    
    Platform.requestObjectDeletion();
  }

  /***
   * Gets the current state of the Application.
   * 
   * @return true if the current application state is SECURED.
   */
  static boolean getAppletSecuredState() {
    return (GPSystem.getCardContentState() == APPLICATION_SECURED);
  }

  /***
   * Sets the current state of the Application. NOTE: Calling this more than once will have no
   * effect.
   */
  static void setAppletSecuredState() {
    if (GPSystem.getCardContentState() == GPSystem.APPLICATION_SELECTABLE) {
      GPSystem.setCardContentState(APPLICATION_SECURED);
    }
  }

  @Override
  public boolean select() {
    // Ensure that the ChannelSCP instance is initialised (we can't do this in the constructor)
    // because GPSystem.getSecureChannel() explictly says: This method shall not be invoked from 
    // the Applet.install() method.
    channelSCP.init();

    // Check if we are permitted to be selected over the current interface. If not,
    // decline to be selected, which means the only way to recover this is to be used over a
    // contact interface.
    return piv.isInterfacePermitted();
  }

  @Override
  public void deselect() {
    
    //
    // SPECIAL CONDITION: Check the ERROR STATE
    //
    if (errorState[0] == ERROR_STATE_CAST_FAILURE) {
      //
      // FIPS 140: Put the module into an infinite loop, effectively killing it until reset.
      // It is a requirement of ISO 19790 that conditional algoroithm self-test failures result
      // in no security functions and no data output from the entire module. Since we cannot
      // directly induce this from the OS, we go into an infinite loop which has the effect of
      // locking the card until reset.
      //
      while (true) { // NOSONAR (Deliberate - See above notes)
      }
    }

    // Reset any security domain session (see resetSecurity() documentation)
    // NOTE: The role will be reset by the piv.deselect() method.
    channelSCP.reset();

    //
    // The PIV applet specification defines rules for how to manage security
    // conditions when
    // it is selected or deselected. These rules/requirements are described in
    // SP800-73-4 Part 2 - 3.1.1 - SELECT Card Command, and can be simplified as follows:
    //
    // a. If the PIV applet is not selected and becomes selected, the security
    // conditions must be reset.
    // b. If the PIV applet is selected and becomes not selected (i.e. a different
    // applet is selected), then the PIV applet becomes selected again, the security
    // conditions must be reset.
    // c. If the PIV applet is selected and a select command is issued again for the
    // PIV applet (i.e. it is re-selected), then the security conditions must not be
    // reset.
    // d. If the PIV applet is selected and a select command is issued for a
    // non-existent applet, then the PIV applet should remain selected and the security
    // conditions must not be reset.

    // Reset the PIV security status only if we are not reselecting the current applet
    piv.deselect(reSelectingApplet());
  }

  public void uninstall() {
    //
    // NOTE:
    // - Get rid of all static instances that would prevent GP from deleting the
    // applet instance without also deleting the corresponding package
    TLVReader.terminate();
    TLVWriter.terminate();
    Platform.terminate();
  }

  @Override
  public void process(APDU apdu) {

    // Check the applet error state to prevent any further functionality in the event of CAST failure.
    if (errorState[0] == ERROR_STATE_CAST_FAILURE) {
      ISOException.throwIt(Constants.SW_CAST_FAILURE);
    }

    // Retrieve the CLA/INS together and strip the chaining/secure messaging bits
    byte[] buffer = apdu.getBuffer();

    //
    // PROCESS APPLICATION COMMANDS
    //
    if (apdu.isISOInterindustryCLA()) {
      try {
        switch (buffer[ISO7816.OFFSET_INS]) {

        case INS_ISO7816_GET_RESPONSE:
          // Do nothing, just process
          break;

        case INS_PIV_SELECT:
          processPIV_SELECT(apdu);
          break;

        case INS_PIV_GET_DATA:
          processPIV_GET_DATA(apdu);
          break;

        case INS_PIV_VERIFY:
          processPIV_VERIFY(apdu);
          break;

        case INS_PIV_CHANGE_REFERENCE_DATA:
          processPIV_CHANGE_REFERENCE_DATA(apdu);
          break;

        case INS_PIV_RESET_RETRY_COUNTER:
          processPIV_RESET_RETRY_COUNTER(apdu);
          break;

        case INS_PIV_GENERAL_AUTHENTICATE:
          processPIV_GENERAL_AUTHENTICATE(apdu);
          break;

        case INS_PIV_PUT_DATA:
          processPIV_PUT_DATA(apdu);
          break;

        case INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR:
          processPIV_GENERATE_ASYMMETRIC_KEYPAIR(apdu);
          break;

        default:
          // Invalid INS
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
        }
      } catch (ISOException ex) {
        if (pApdu.getSecureChannel() == PIVAPDU.SECURE_CHANNEL_PIVSM) {
          pApdu.setOutgoingStatus(ex.getReason());
        } else {
          throw ex;
        }
      } catch (Exception ex) {
        if (pApdu.getSecureChannel() == PIVAPDU.SECURE_CHANNEL_PIVSM) {
          pApdu.setOutgoingStatus(ISO7816.SW_UNKNOWN);
        } else {
          ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
      }

      // 
      // Process Response
      //
      if (pApdu.getState() == PIVAPDU.STATE_OUTGOING) {
        pApdu.processOutgoing(apdu);
      }

    } else {
      //
      // PROCESS GLOBALPLATFORM AND TEST / DIAGNOSTIC COMMANDS
      // NOTE: The commands below do not make use of PIVAPDU, just APDU
      //
      switch (buffer[ISO7816.OFFSET_INS]) {

      case INS_GP_INITIALIZE_UPDATE:
        processGP_INIT_UPDATE(apdu);
        return;

      case INS_GP_EXTERNAL_AUTHENTICATE:
        processGP_EXTERNAL_AUTH(apdu);
        return;

      case INS_DEBUG_RUN_ACVP_KDF:
        processTEST_RUN_ACVP_KDF(apdu);
        return;

      case INS_DEBUG_RUN_ACVP_KC:
        processTEST_RUN_ACVP_KC(apdu);
        return;

      default:
        // Invalid INS
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return;
      }
    }
  }

  /**
   * Process the PIV 'SELECT' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_SELECT(APDU apdu) {

    // FIPS140:
    //
    // This can be used by the following roles:
    // - Public
    //
    // This implements the following Services:
    // - Applet Selection
    //
    // This implements the following Service States:
    // - OP_CMD_SELECT

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [X] R-APDU Response Data
    // [ ] SCP03
    // [ ] PIV-SM
    // [ ] Command Chaining
    // [X] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete
    if (!pApdu.isCompleteCommand()) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2 - This must be called only when the applet selection is indicated
    if (!selectingApplet()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // NOTE: We don't check the data because we could not have been selected if
    // it wasn't correct.

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the PIV 'SELECT' command in all cases to handle the PIV SELECT
    // rules
    piv.select(pApdu);
  }

  /**
   * Process the PIV 'GET DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GET_DATA(APDU apdu) {

    // FIPS140:
    //
    // This can be used by the following roles:
    // - All (NOTE: SSP access rules apply on a per-object basis)
    //
    // This implements the following Authentication Methods and Services:
    // - Data Object Reading
    //
    // This implements the following Service States:
    // - OP_CMD_GET_DATA

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [X] R-APDU Response Data
    // [X] SCP03
    // [X] PIV-SM
    // [ ] Command Chaining
    // [X] Response Chaining
    // [X] Object Reading
    // [ ] Object Writing

    final byte PARAM_P1 = (byte) 0x3F;
    final byte PARAM_P2_STANDARD = (byte) 0xFF;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete
    if (!pApdu.isCompleteCommand()) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 3 - The P1 parameter value must be equal to the constant 3F
    if (pApdu.getP1() != PARAM_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the appropriate processor
    if (pApdu.getP2() == PARAM_P2_STANDARD) {
      piv.getData(pApdu);
    } else {
      piv.getDataExtended(pApdu);
    }
  }

  /**
   * Process the PIV 'VERIFY' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_VERIFY(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - AUTH_L_PIN
    // - AUTH_G_PIN
    //
    // This implements the following Service States:
    // - OP_CMD_VERIFY
    // - OP_CMD_VERIFY_GET_STATUS
    // - OP_CMD_VERIFY_RESET_STATUS

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // -- For OP_CMD_VERIFY, APDU case 3S is used (Command data expected, No
    // response data)
    // -- For OP_CMD_VERIFY_GET_STATUS and OP_CMD_VERIFY_RESET_STATUS, APDU case 1
    // is used
    // [ ] R-APDU Response Data
    // [ ] SCP03
    // [X] PIV-SM
    // [ ] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    final byte CONST_P1_AUTH = (byte) 0x00;
    final byte CONST_P1_RESET = (byte) 0xFF;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete
    if (!pApdu.isCompleteCommand()) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2 - The P1 value must be equal to the constant CONST_P1_AUTH or CONST_P1_RESET
    // NOTE: This is handled by the mode selection below

    // PRE-CONDITION 3 - If the P1 value is set to CONST_P1_RESET, the data field must be absent
    // NOTE: This is handled by the mode selection below

    byte mode;

    // CASE 1 - If P1='00', and Lc and the command data field are absent, the
    // command can be
    // used to retrieve the number of further retries allowed ('63 CX'), or to check
    // whether
    // verification is not needed ('90 00').
    if (pApdu.getP1() == CONST_P1_AUTH && inLength == Constants.ZERO_SHORT) {
      // Retrieve the authentication status using the PIN reference supplied in P2
      mode = PIV.VERIFY_MODE_GET_STATUS;
    }
    // CASE 2 - If P1='FF', and Lc and the command data field are absent, the
    // command shall reset
    // the security status of the key reference in P2.
    else if (pApdu.getP1() == CONST_P1_RESET && inLength == Constants.ZERO_SHORT) {
      // Reset the authentication status using the PIN reference supplied in P2
      mode = PIV.VERIFY_MODE_RESET;
    }
    // CASE 3 - If P1='00', and Lc and the command data field are present, then the
    // authentication
    // data in the command data field shall be compared against the reference data
    // associated with the PIN reference [...]
    else if (pApdu.getP1() == CONST_P1_AUTH && inLength != Constants.ZERO_SHORT) {
      // Verify using the PIN reference supplied in P2
      mode = PIV.VERIFY_MODE_AUTH;
    } else {
      // If we reached here, then none of the cases applied and we are in an error
      // condition
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the appropriate PIV 'Verify' command
    piv.verify(mode, pApdu.getP2(), pApdu, inLength);

    // Done, no response data required
  }

  /**
   * Process the PIV 'CHANGE REFERENCE DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_CHANGE_REFERENCE_DATA(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - Manage Verification Data
    // - Manage Application Configuration
    //
    // This implements the following Service States:
    // - OP_CMD_CHANGE_REF_DATA
    // - OP_CMD_CHANGE_REF_DATA_ADMIN

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [ ] R-APDU Response Data
    // [X] SCP03 (Required for P1_ADMIN)
    // [X] PIV-SM
    // [X] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    final byte P1_STANDARD = (byte) 0x00;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete (No error, just return)
    if (!pApdu.isCompleteCommand()) {
      return;
    }

    // PRE-CONDITION 2 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    /*
     * EXECUTION STEPS
     */

    // We use the APDU buffer to get just P1/P2
    byte[] buffer = apdu.getBuffer();
    byte mechanism = buffer[ISO7816.OFFSET_P1];
    byte id = buffer[ISO7816.OFFSET_P2];
    boolean standard = (id == Constants.ID_AUTH_GLOBAL_PIN || id == Constants.ID_AUTH_LOCAL_PIN
        || id == Constants.ID_AUTH_PUK) && mechanism == P1_STANDARD;

    // STEP 1 - Call the appropriate processor method
    if (standard) {
      piv.changeReferenceData(id, pApdu);
    } else {
      piv.changeReferenceDataAdmin(id, mechanism, pApdu);
    }
  }

  /**
   * Process the PIV 'RESET RETRY COUNTER' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_RESET_RETRY_COUNTER(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - AUTH_PUK
    // - Reset Verification Data
    //
    // This implements the following Service States:
    // - OP_CMD_RESET_RETRY_COUNTER

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [ ] R-APDU Response Data
    // [ ] SCP03
    // [X] PIV-SM
    // [ ] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    final byte CONST_P1 = (byte) 0x00;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete
    if (!pApdu.isCompleteCommand()) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 3 - The P1 value must be equal to the constant CONST_P1
    if (pApdu.getP1() != CONST_P1) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the PIV handler
    piv.resetRetryCounter(pApdu.getP2(), pApdu);
  }

  /**
   * Process the PIV 'GENERAL AUTHENTICATE' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GENERAL_AUTHENTICATE(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - AUTH_SYM_EXT
    // - AUTH_SYM_MUT
    // - PIV Digital Signature
    // - PIV RSA Key Transport
    // - PIV ECDH Key Agreement
    // - PIV Card Authentication
    // - PIV Key Holder Authentication
    // - PIV Secure Messaging
    //
    // This implements the following Service States:
    // - OP_CMD_GENERAL_AUTH

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [ ] R-APDU Response Data
    // [ ] SCP03
    // [X] PIV-SM
    // [X] Command Chaining
    // [X] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete (No error, just return to allow the next part)
    if (!pApdu.isCompleteCommand()) {
      return;
    }

    // PRE-CONDITION 2 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the PIV GENERAL AUTHENTICATE method
    try {
      piv.generalAuthenticate(pApdu.getP2(), pApdu.getP1(), pApdu);
    } catch (ISOException ex) {
      // FIPS140: Special rule to catch a CAST failure and induce an applet failure.
      // NOTE: This will cause the card to lock when the applet is next de-selected or used.
      if (ex.getReason() == Constants.SW_CAST_FAILURE) {
        errorState[0] = ERROR_STATE_CAST_FAILURE;
      }
      throw ex;
    } catch (Exception ex) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    // Done
  }

  /**
   * Processes the PIV 'PUT DATA' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_PUT_DATA(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - Manage Application Data
    // - Manage Application Configuration
    //
    // This implements the following Service States:
    // - OP_CMD_PUT_DATA
    // - OP_CMD_PUT_DATA_ADMIN

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [ ] R-APDU Response Data
    // [X] SCP03
    // [ ] PIV-SM
    // [X] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [X] Object Writing
    final byte PARAM_P1 = (byte) 0x3F;
    final byte PARAM_P2_STANDARD = (byte) 0xFF;
    final byte PARAM_P2_ADMIN = (byte) 0x00;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - If this is a continuation of a previous chained object, just return
    if (pApdu.getState() == PIVAPDU.STATE_INCOMING_OBJECT) {
      return;
    }

    // PRE-CONDITION 2 - If this is the completion of a previous chained object, just return
    if (pApdu.getState() == PIVAPDU.STATE_INCOMING_OBJECT_COMPLETE) {
      return;
    }

    // PRE-CONDITION 3 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 4 - The parameter values must be equal to the constant '3FFF'
    // (standard) or '3F00' (administrative)
    if (pApdu.getP1() != PARAM_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    short admin;
    switch (pApdu.getP2()) {
    case PARAM_P2_STANDARD:
      admin = Constants.FALSE_SHORT;
      break;

    case PARAM_P2_ADMIN:
      admin = Constants.TRUE_SHORT;
      break;

    default:
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return; // Keep compiler happy
    }

    // PRE-CONDITION 5 - If admin, the command must be complete (Not an error, just return)
    if (Constants.TRUE_SHORT == admin && !pApdu.isCompleteCommand()) {
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the appropriate handler
    if (Constants.TRUE_SHORT == admin) {
      piv.putDataAdmin(pApdu);
    } else {
      //
      // NOTES:
      // The putData() command is responsible for setting up the incoming object, as
      // it has the internal reference to the PIV Data Object buffer. The method returns the
      // offset to start writing from as it skips the identifier/tag bytes.
      //
      short offset;
      try {
        offset = piv.putData(pApdu);
      } catch (ISOException ex) {
        throw ex;
      } catch (Exception ex) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
        return; // Keep compiler happy
      }

      // Process the first block if we have any to write (a clear() would skip this)
      if (offset > Constants.ZERO_SHORT) {
        // Reduce inLength by offset-dataOffset to get the number of bytes in this APDU
        inLength -= offset;
        inLength += pApdu.getDataOffset();

        // STEP 2 - Process the first block to the destination object, skipping unwrapping
        pApdu.processIncomingObject(offset, inLength, apdu.isCommandChainingCLA());
      }
    }
  }

  /**
   * Process the PIV 'GENERATE ASYMMETRIC KEYPAIR' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_GENERATE_ASYMMETRIC_KEYPAIR(APDU apdu) {

    // FIPS140:
    //
    // This implements the following Authentication Methods and Services:
    // - PIV Key Generation
    //
    // This implements the following Service States:
    // - OP_CMD_GENERATE_KEYPAIR

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [X] R-APDU Response Data
    // [X] SCP03
    // [ ] PIV-SM
    // [ ] Command Chaining
    // [X] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    final byte CONST_P1 = (byte) 0x00;

    // Process the incoming frame
    short inLength = apdu.setIncomingAndReceive();
    inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command must be complete
    if (!pApdu.isCompleteCommand()) {
      pApdu.reset();
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2 - The command must contain data
    if (inLength <= Constants.ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1
    if (pApdu.getP1() != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    byte id = pApdu.getP2();

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Call the PIV GENERATE ASYMMETRIC KEY command
    piv.generateKeyPair(id, pApdu);

    // Done
  }

  /**
   * Processes the GlobalPlatform Secure Channel Protocol (SCP) step 1
   *
   * @param apdu  The APDU to process.
   * @param reset If true, reset the secure channel
   */
  private void processGP_INIT_UPDATE(APDU apdu) {

    // FIPS140:
    //
    // This can be used by the following roles:
    // - Public
    //
    // This implements the following Services and Authentication Methods:
    // - Manage Secure Channel
    // - AUTH_SCP03
    //
    // This implements the following Service States:
    // - OP_CMD_GP_SECURECHANNEL

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [X] R-APDU Response Data
    // [ ] SCP03
    // [ ] PIV-SM
    // [ ] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - Administration must be permitted on the current interface
    if (!piv.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Explicitly clear any existing PIV Secure Messaging channel
    piv.getSecureMessaging().reset();

    // STEP 2 - Explicitly clear any pApdu command
    pApdu.reset();

    // STEP 3 - Call the channel's processSecurity method
    // NOTES:
    // - This is a special case where we MUST pass through the original APDU, as the
    // GP processSecurity() method requires it.
    // - We must NOT call setIncomingAndReceive for this method as it is handled
    // inside processSecurity()
    short outLength = channelSCP.initializeUpdate(apdu);

    // STEP 4 - Send the response (the response data is written to the CDATA section)
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLength);
  }

  /**
   * Processes the GlobalPlatform Secure Channel Protocol (SCP) step 2
   *
   * @param apdu  The APDU to process.
   * @param reset If true, reset the secure channel
   */
  private void processGP_EXTERNAL_AUTH(APDU apdu) {

    // FIPS140:
    //
    // This can be used by the following roles:
    // - Public
    //
    // This implements the following Services and Authentication Methods:
    // - Manage Secure Channel
    // - AUTH_SCP03
    //
    // This implements the following Service States:
    // - OP_CMD_GP_SECURECHANNEL

    // Permitted / Utilised Modes:
    // ---------------------------
    // [X] C-APDU Command Data
    // [X] R-APDU Response Data
    // [ ] SCP03
    // [ ] PIV-SM
    // [ ] Command Chaining
    // [ ] Response Chaining
    // [ ] Object Reading
    // [ ] Object Writing

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - Administration must be permitted on the current interface
    if (!piv.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Explicitly clear any existing PIV Secure Messaging channel
    piv.getSecureMessaging().reset();

    // STEP 2 - Explicitly clear any pApdu command
    pApdu.reset();

    // STEP 3 - Call the channel method
    // NOTE:
    // - We must NOT call setIncomingAndReceive for this method as it is handled
    // inside processSecurity()
    short outLength = channelSCP.externalAuthenticate(apdu);

    // STEP 4 - Set the operator role for PIV
    piv.setRoleAdmin();

    // STEP 5 - Send the response (the response data is written to the CDATA section)
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLength);
  }

  /////////////////////////////////////////////////////////////////////////////
  //
  // !! TEST AND COMPLIANCE FUNCTIONALITY !!
  // 
  // The functionality below is designed to be automatically compiled-out if
  // the corresponding debug flags are not set in the Config class.
  //
  // In addition, the Applet will prevent installation if the any of these 
  // feature flags are enabled whilst the Config.VERSION_DEBUG flag is not set.
  // 
  /////////////////////////////////////////////////////////////////////////////

  // PERSISTENT - FIPS ACVP algorithm objects
  // NOTE: These will never be instantiated unless the ACVP algorithms are enabled in debug mode
  private AESKey acvpKey = null;
  private Signature acvpCmac = null;

  private void processTEST_RUN_ACVP_KDF(APDU apdu) {
    // We check the flag here, which will ensure that the code compiles out if it is false
    if (Config.DEBUG_FIPS_RUN_ACVP) {

      // Process the incoming frame
      short inLength = apdu.setIncomingAndReceive();
      inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

      // FORMAT:    
      // 02 = Algorithm (INTEGER (0..127))
      // 02 = DKM Length (INTEGER (0..128))
      // 04 = Z (OCTET STRING)
      // 04 = PartyUInfo (OCTET STRING)
      // 04 = PartyVInfo (OCTET STRING)
      TLVReader reader = TLVReader.getInstance(pApdu.getData(), pApdu.getDataOffset(), inLength);

      // Sequence
      if (!reader.match((byte)0x30)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // Algorithm
      if (!reader.match(TLV.ASN1_INTEGER)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      byte algorithm = reader.toByte();
      reader.moveNext();

      // DKM Length
      if (!reader.match(TLV.ASN1_INTEGER)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short dkmLength = reader.toShort();
      reader.moveNext();

      // Z
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short zOffset = reader.getDataOffset();
      short zLength = reader.getLength();
      reader.moveNext();

      // PartyUInfo
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short uOffset = reader.getDataOffset();
      short uLength = reader.getLength();
      reader.moveNext();

      // PartyUInfo
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short vOffset = reader.getDataOffset();
      short vLength = reader.getLength();
      reader.moveNext();

      // Create the requested digest if it isn't already set to this
      SP80056KDAOneStep.doFinal(algorithm, pApdu.getData(), zOffset, zLength, uOffset, uLength, vOffset, vLength,
          apdu.getBuffer(), (short) 0, dkmLength);

      apdu.setOutgoingAndSend((short) 0, dkmLength);
    } else {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  private void processTEST_RUN_ACVP_KC(APDU apdu) {
    // We check the flag here, which will ensure that the code compiles out if it is false
    if (Config.DEBUG_FIPS_RUN_ACVP) {
      
      // Process the incoming frame
      short inLength = apdu.setIncomingAndReceive();
      inLength = pApdu.processIncomingAPDU(apdu, ISO7816.OFFSET_CDATA, inLength);

      // FORMAT:    
      // 04 = MacKey (OCTET STRING)
      // 04 = infoR (OCTET STRING)
      // 04 = infoP (OCTET STRING)
      TLVReader reader = TLVReader.getInstance(pApdu.getData(), pApdu.getDataOffset(), inLength);

      // Sequence
      if (!reader.match((byte)0x30)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // MacKey
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short kOffset = reader.getDataOffset();
      short kLength = reader.getLength();
      reader.moveNext();

      // infoR
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short rOffset = reader.getDataOffset();
      short rLength = reader.getLength();
      reader.moveNext();

      // infoP
      if (!reader.match(TLV.ASN1_OCTET_STRING)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short pOffset = reader.getDataOffset();
      short pLength = reader.getLength();
      reader.moveNext();

      // OPTIONAL - qeP / qeR
      // NOTE: The ACVP tests provide ephemereal data from both the Server (R) and IUT (P)
      // roles, however PIV only ever requires the qeP data, so the test harness just provides
      // both, concatenated in this field
      short qePROffset = (short) -1;
      short qePRLength = (short) 0;
      if (reader.match(TLV.ASN1_OCTET_STRING)) {
        qePROffset = reader.getDataOffset();
        qePRLength = reader.getLength();
      }

      // Create the cryptographic objects as required
      if (acvpCmac == null) {
        acvpCmac = Platform.Cryptography.getCMAC();
      }
      short kLengthBits = (short) (kLength * 8);
      if (acvpKey == null || acvpKey.getSize() != kLengthBits) {
        acvpKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, kLengthBits, false);
      }
      acvpKey.setKey(pApdu.getData(), kOffset);

      short length = SP80056KasKc.doFinal(acvpCmac, acvpKey, pApdu.getData(), rOffset, rLength, pOffset, pLength,
          qePROffset, qePRLength, apdu.getBuffer(), (short) 0);

      apdu.setOutgoingAndSend((short) 0, length);
    } else {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

}
