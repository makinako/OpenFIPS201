/******************************************************************************
MIT License

  Project: OpenFIPS201
Copyright: (c) 2017 Commonwealth of Australia
   Author: Kim O'Sullivan - Makina (kim@makina.com.au)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

package com.makina.security.OpenFIPS201;

import javacard.framework.*;

/**
 * Implements FIPS201-2 according to NIST SP800-73-4.
 *
 * It implements the following functionality:
 * - Compiles to Javacard 2.2.2 for maximum compatibility
 * - A flexible filesystem that can be defined easily without recompilation
 * - A flexible key store that defines key roles instead of hard-coding which key is used for what function
 * - Secure personalisation over SCP w/CEnc+CMac using the CHANGE REFERENCE DATA and PUT DATA commands
 *
 * The following is out-of-scope in this revision:
 * - Elliptic curve cryptography mechanisms
 * - Virtual contact interface
 * - Secure messaging using Opacity
 * - Biometric on-card comparison (OCC)
 */
public final class PIV {

    //
    // Persistent Objects
    //

    // Data Store
    private PIVDataObject firstDataObject;

    // Command Chaining Handler
    private ChainBuffer chainBuffer;

    // TLV management objects
    TLVReader tlvReader;
    TLVWriter tlvWriter;

    // Cryptography Service Provider
    private PIVSecurityProvider cspPIV;

    //
    // Transient Objects
    //

    // A RAM working area to hold intermediate data and outgoing buffers
    private byte[] scratch;

    // Transient buffer allocation
    public static final short LENGTH_SCRATCH			= (short)284;

    // Holds any authentication related intermediery state
    private byte[] authenticationContext;

    // The current authentication stage
    private static final short OFFSET_AUTH_STATE		= (short)0;

    // The key id used in the current authentication
    private static final short OFFSET_AUTH_ID			= (short)1;

    // The key mechanism used in the current authentication
    private static final short OFFSET_AUTH_MECHANISM	= (short)2;

    // The GENERAL AUTHENTICATE challenge buffer
    private static final short OFFSET_AUTH_CHALLENGE	= (short)3;

    // The length to allocate for holding CHALLENGE or WITNESS data for general authenticate
    // NOTE: Since RSA is only involved in INTERNAL AUTHENTICATE, we only need to cater for
    //		 up to an AES block size
    private static final short LENGTH_CHALLENGE			= (short)16;
    private static final short LENGTH_AUTH_STATE		= (short)(5 + LENGTH_CHALLENGE);

    /*
     * PIV APPLICATION CONSTANTS
     */


    // GENERAL AUTHENTICATE is in its initial state
    private static final short AUTH_STATE_NONE		= (short)0;

    // A CHALLENGE has been requested by the client application (Basic Authentication)
    private static final short AUTH_STATE_EXTERNAL	= (short)1;

    // A WITNESS has been requested by the client application (Mutual Authentication)
    private static final short AUTH_STATE_MUTUAL	= (short)2;

    //
    // PIN key reference definitions
    //
    public static final byte ID_KEY_GLOBAL_PIN 	= (byte)0x00;
    public static final byte ID_KEY_PIN 		= (byte)0x80;
    public static final byte ID_KEY_PUK 		= (byte)0x81;

    //
    // Cryptographic Mechanism Identifiers
    // SP800-73-4 Part 1: 5.3 - Table 5 and
    // SP800-78-4 5.3 - Table 6-2
    //

    public static final byte ID_ALG_DEFAULT		= (byte)0x00; // This maps to TDEA_3KEY
    public static final byte ID_ALG_TDEA_3KEY	= (byte)0x03;
    public static final byte ID_ALG_RSA_1024	= (byte)0x06;
    public static final byte ID_ALG_RSA_2048	= (byte)0x07;
    public static final byte ID_ALG_AES_128		= (byte)0x08;
    public static final byte ID_ALG_AES_192		= (byte)0x0A;
    public static final byte ID_ALG_AES_256		= (byte)0x0C;

    //
    // PIV-specific ISO 7816 STATUS WORD (SW12) responses
    //
    public static final short SW_RETRIES_REMAINING 		= (short)0x63C0;
    public static final short SW_REFERENCE_NOT_FOUND 	= (short)0x6A88;
    public static final short SW_OPERATION_BLOCKED 		= (short)0x6983;

    /**
     * Constuctor
     *
     * @param chainBuffer A reference to the shared chainBuffer for multi-frame APDU support
     */
    public PIV(ChainBuffer chainBuffer) {

        //
        // Data Allocation
        //

        // Create our transient buffers
        scratch = JCSystem.makeTransientByteArray(LENGTH_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
        authenticationContext = JCSystem.makeTransientByteArray(LENGTH_AUTH_STATE, JCSystem.CLEAR_ON_DESELECT);

        // Create our chainBuffer reference and make sure its state is cleared
        this.chainBuffer = chainBuffer;
        chainBuffer.reset();

        // Create our PIV Security Provider
        cspPIV = new PIVSecurityProvider();

        // Create our TLV objects
        tlvReader = new TLVReader();
        tlvWriter = new TLVWriter();

        //
        // Pre-Personalisation
        //

        // Set the default PIN value (except for the Global PIN)
        if (Config.FEATURE_PIN_INIT_RANDOM) {
            cspPIV.generateRandom(scratch, (short)0, Config.PIN_LENGTH_MAX);
            cspPIV.cardPIN.update(scratch, (short)0, Config.PIN_LENGTH_MAX);
            cspPIV.zeroise(scratch, (short)0, Config.PIN_LENGTH_MAX);
        } else {
            cspPIV.cardPIN.update(Config.DEFAULT_PIN, (short)0, (byte)Config.DEFAULT_PIN.length);
        }

        // Set the default PUK value
        if (Config.FEATURE_PUK_INIT_RANDOM) {
            // Generate a random value
            cspPIV.generateRandom(scratch, (short)0, Config.PIN_LENGTH_MAX);
            cspPIV.cardPUK.update(scratch, (short)0, Config.PIN_LENGTH_MAX);
            cspPIV.zeroise(scratch, (short)0, Config.PIN_LENGTH_MAX);
        } else {
            // Use the default from our configuration file
            cspPIV.cardPUK.update(Config.DEFAULT_PUK, (short)0, (byte)Config.DEFAULT_PUK.length);
        }
    }

    /**
     * Called when this applet is selected, returning the APT object
     *
     * @param buffer The APDU buffer to write the APT to
     * @param offset The starting offset of the CDATA section
     * @param length The length of the CDATA section
     * @return The length of the returned APT object
     */
    public short select(byte[] buffer, short offset, short length) {

        //
        // PRE-CONDITIONS
        //

		// NONE

        //
        // EXECUTION STEPS
        //

        // STEP 1 - Return the APT
        Util.arrayCopyNonAtomic(Config.DEFAULT_APT, (short)0, buffer, offset, (short)Config.DEFAULT_APT.length);

        return (short)Config.DEFAULT_APT.length;
    }

    /**
     * Handles the PIV requirements for deselection of the application.
     * Although this is not explicitly stated as a PIV card command, its functionality is implied in the SELECT
     */
    public void deselect() {

        // If the currently selected application is the PIV Card Application when the SELECT command is given
        // and the AID in the data field of the SELECT command is either the AID of the PIV Card Application or
        // the right-truncated version thereof, then the PIV Card Application shall continue to be the currently
        // selected card application and the setting of all security status indicators in the PIV Card Application
        // shall be unchanged.

        // If the currently selected application is the PIV Card Application when the SELECT command is given
        // and the AID in the data field of the SELECT command is not the PIV Card Application (or the right truncated
        // version thereof), but a valid AID supported by the ICC, then the PIV Card Application shall be
        // deselected and all the PIV Card Application security status indicators in the PIV Card Application shall
        // be set to FALSE.

        // Reset all security conditions in the security provider
        cspPIV.resetSecurityStatus();
    }

    /**
     * The GET DATA card command retrieves the data content of the single data object whose tag is given in
     * the data field.
     *
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA section
     * @param length The length of the CDATA section
     * @return The length of the entire data object
     */
    public short getData(byte[] buffer, short offset, short length) {

        final byte CONST_TAG 		= (byte)0x5C;
        final byte CONST_TAG_MIN 	= (byte)0x01;
        final byte CONST_TAG_MAX 	= (byte)0x03;

        final byte CONST_TAG_DISCOVERY		= (byte)0x7E;
        final byte CONST_TAG_BIOMETRIC_1	= (byte)0x7F;
        final byte CONST_TAG_BIOMETRIC_2	= (byte)0x61;
        final byte CONST_TAG_NORMAL_1		= (byte)0x5F;
        final byte CONST_TAG_NORMAL_2		= (byte)0xC1;

        final short CONST_LEN_DISCOVERY	= (short)0x01;
        final short CONST_LEN_BIOMETRIC	= (short)0x02;

        //
        // PRE-CONDITIONS
        //

        // PRE-CONDITION 1 - The 'TAG' data element must be present
        // NOTE: This is parsed manually rather than going through a TLV parser
        if (buffer[offset++] != CONST_TAG) ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Check SW12

        // PRE-CONDITION 2 - The 'LENGTH' data element must be between CONST_TAG_MIN and CONST_TAG_MAX
        length = (short)(buffer[offset++] & 0xFF);
        if (length < CONST_TAG_MIN || length > CONST_TAG_MAX) ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Check SW12

        //
        // Retrieve the data object TAG identifier
        // NOTE: All objects in the datastore have had their tag reduced to one byte, which is
        //		 always the least significant byte of the tag.
        //

        byte id = 0;

        // SPECIAL OBJECT - DISCOVERY OBJECT
        if ((length == (short)1) && buffer[offset] == CONST_TAG_DISCOVERY) {
            id = CONST_TAG_DISCOVERY;
        }

        // SPECIAL OBJECT - BIOMETRIC GROUP TEMPLATE
        else if ((length == (short)2) && buffer[offset] == CONST_TAG_BIOMETRIC_1) {
            offset++;
            if (buffer[offset] != CONST_TAG_BIOMETRIC_2) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            id = CONST_TAG_BIOMETRIC_2;
        }
        // ALL OTHER OBJECTS
        else if ((length == (short)3) && buffer[offset] == CONST_TAG_NORMAL_1) {
            offset++; // Move to the 2nd byte
            if (buffer[offset] != CONST_TAG_NORMAL_2) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            offset++; // Move to the 3rd byte
            id = buffer[offset]; // Store it as our object ID
        }
        // Invalid Object
        else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        PIVDataObject data = findDataObject(id);
        if (data == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        // PRE-CONDITION 4 - The access rules must be satisfied for the requested object
        if (!cspPIV.checkAccessModeObject(data)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // PRE-CONDITION 5 - The object must be initialised with data
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
        }

        //
        // EXECUTION STEPS
        //

        // STEP 1 - Set up the outgoing chainbuffer
        length = (short)data.content.length;
        chainBuffer.setOutgoing(data.content, (short)0, length, false);

        // Done - return how many bytes we will process
        return length;
    }

    /**
     * The PUT DATA card command completely replaces the data content of a single data object in
     * the PIV Card Application with new content.
     *
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA section
     * @param length The length of the CDATA section
     */
    public void putData(byte[] buffer, short offset, short length) {

        final byte CONST_TAG 		= (byte)0x5C;
        final byte CONST_TAG_MIN 	= (byte)0x01;
        final byte CONST_TAG_MAX 	= (byte)0x03;
        final byte CONST_DATA		= (byte)0x53;

        final byte CONST_TAG_DISCOVERY		= (byte)0x7E;
        final byte CONST_TAG_BIOMETRIC_1	= (byte)0x7F;
        final byte CONST_TAG_BIOMETRIC_2	= (byte)0x61;
        final byte CONST_TAG_NORMAL_1		= (byte)0x5F;
        final byte CONST_TAG_NORMAL_2		= (byte)0xC1;

        final short CONST_LEN_DISCOVERY	= (short)0x01;
        final short CONST_LEN_BIOMETRIC	= (short)0x02;

        //
        // PRE-CONDITIONS
        //

        // Store the supplied data offset so we can use it to calculate the length of the object later
        short initialOffset = offset;

        // PRE-CONDITION 1 - The access rules must be satisfied for administrative access
        if (!cspPIV.checkAccessModeAdmin(false) ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte id = 0;

        // SPECIAL OBJECT - DISCOVERY OBJECT
        // PRE-CONDITION 2A - If the special 'DISCOVERY OBJECT' is being written, the tag specified by
        //					  CONST_TAG_DISCOVERY must be present
        if (buffer[offset] == CONST_TAG_DISCOVERY) {
            id = CONST_TAG_DISCOVERY;
            // We don't move the buffer for this special object to include the special data object tag
        }

        // SPECIAL OBJECT - BIOMETRIC GROUP TEMPLATE
        // PRE-CONDITION 2B - If the special 'BIOMETRIC GROUP TEMPLATE' is being written, the tag values
        //					  specified by CONST_TAG_BIOMETRIC_1 and CONST_TAG_BIOMETRIC_2 must be present
        else if (buffer[offset] == CONST_TAG_BIOMETRIC_1) {
            if ((short)(buffer[offset] + 1) != CONST_TAG_BIOMETRIC_2) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
            id = CONST_TAG_BIOMETRIC_2;
            // We don't move the buffer for this special object to include the special data object tag
        }

        //
        // ALL OTHER OBJECTS (Must have the TAG LIST value)
        //
        else if (buffer[offset] == CONST_TAG) {

            //
            // Retrieve the data object TAG identifier
            // NOTE: All objects in the datastore have had their tag reduced to one byte, which is
            //		 always the least significant byte of the tag.
            //

            offset++; // Move to the length field

            // PRE-CONDITION 3 - The 'TAG LIST' tag must have a length of between CONST_TAG_MIN and CONST_TAG_MAX
            if (buffer[offset] < CONST_TAG_MIN || buffer[offset] > CONST_TAG_MAX) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            offset++; // Move to the 1st byte of the tag
            if (buffer[offset] != CONST_TAG_NORMAL_1) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
            offset++; // Move to the 2nd byte
            if (buffer[offset] != CONST_TAG_NORMAL_2) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
            offset++; // Move to the 3rd byte
            id = buffer[offset]; // Store it as our object ID
            offset++; // Move to the DATA element

            // PRE-CONDITION 4 - The 'DATA' tag must be present in the supplied buffer
            if (buffer[offset] != CONST_DATA) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // The offset now holds the correct position for writing the object, including the DATA tag
        }
        // Invalid Object
        else {
            ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }


        // PRE-CONDITION 5 - The tag supplied in the 'TAG LIST' element must exist in the data store
        PIVDataObject obj = findDataObject(id);
        if (obj == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        //
        // EXECUTION STEPS
        //

        // STEP 1 - Calculate the total length of the object to allocate
        short objectLength = TLVReader.getLength(buffer, offset);
        objectLength += (short)(TLVReader.getDataOffset(buffer, offset) - offset);

        // STEP 2 - Allocate the data object
        obj.allocate(objectLength);

        // STEP 3 - Recalculate the length of the first write, to account for the tag element being removed
        length -= (short)(offset - initialOffset);

        // STEP 4 - Set up the incoming chainbuffer
        chainBuffer.setIncomingObject(obj.content, (short)0, objectLength, false);

        // STEP 5 - Start processing the first segment of data here so we can give it our modified offset/length
        chainBuffer.processIncomingObject(buffer, offset, length);
    }

    /**
     * The VERIFY card command initiates the comparison in the card of the reference data indicated
     * by the key reference with authentication data in the data field of the command.
     *
     * @param id The requested PIN reference
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA element
     * @param length The length of the CDATA element
     */
    public void verify(byte id, byte[] buffer, short offset, short length) {

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
        }

        // PRE-CONDITION 2 - If FEATURE_PIN_OVER_CONTACTLESS is not set, the interface must be contact
        if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

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
        if (pin.getTriesRemaining() == (byte)0) ISOException.throwIt(SW_OPERATION_BLOCKED);

        // PRE-CONDITION 5 - If using the contactless interface, the pin retries remaining must not
        //					 fall below the specified intermediate retry amount

        // In order to protect against blocking over the contactless interface, PIV Card Applications
        // that implement secure messaging shall define an issuer-specified intermediate retry value for
        // each of these key references and return '69 83' if the command is submitted over the contactless
        // interface (over secure messaging or the VCI, as required for the key reference) and the current value
        // of the retry counter associated with the key reference is at or below the issuer-specified intermediate
        // retry value. If status word '69 83' is returned, then the comparison shall not be made, and the
        // security status and the retry counter of the key reference shall remain unchanged.
        if ((pin.getTriesRemaining() <= Config.PIN_RETRIES_INTERMEDIATE) && cspPIV.getIsContactless()) {
            ISOException.throwIt(SW_OPERATION_BLOCKED);
        }

        //
        // EXECUTION STEPS
        //

        // Verify the PIN
        if (!pin.check(buffer, offset, (byte)length)) {

            // Check for blocked again
            if (pin.getTriesRemaining() == (byte)0) ISOException.throwIt(SW_OPERATION_BLOCKED);

            // Return the number of retries remaining
            ISOException.throwIt((short)(SW_RETRIES_REMAINING | (short)pin.getTriesRemaining()));
        }

        // Verified, set the PIN ALWAYS flag
        cspPIV.setPINAlways(true);
    }


    /**
     * Implements the variant of the 'VERIFY' command that returns the status of the requested PIN
     * @param id The requested PIN reference
     */
    public void verifyGetStatus(byte id) {

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
        }

        // If P1='00', and Lc and the command data field are absent, the command can be used to retrieve the
        // number of further retries allowed ('63 CX'), or to check whether verification is not needed ('90 00').

        // Check for blocked
        if (pin.getTriesRemaining() == (byte)0) ISOException.throwIt(SW_OPERATION_BLOCKED);

        // If we are not validated
        if (!pin.isValidated()) {
            // Return the number of retries remaining
            ISOException.throwIt((short)(SW_RETRIES_REMAINING | (short)pin.getTriesRemaining()));
        }

        // If we got this far we are authenticated, so just return (9000)
    }

    /**
     * Implements the variant of the 'VERIFY' command that resets the authentication state of
     * the requested PIN
     * 
     * @param id The requested PIN reference
     */
    public void verifyResetStatus(byte id) {

        // The security status of the key reference
        // specified in P2 shall be set to FALSE and the retry counter associated with the key
        // reference shall remain unchanged.

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
        }

        // Reset the requested PIN
        pin.reset();

        // Reset the PIN ALWAYS flag
        cspPIV.setPINAlways(false);
    }

    /**
     * The CHANGE REFERENCE DATA card command initiates the comparison of the authentication data in the command data
     * field with the current value of the reference data and, if this comparison is successful, replaces the reference
     * data with new reference data.
     *
     * @param id The requested PIN reference
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA element
     * @param length The length of the CDATA element
     */
    public void changeReferenceData(byte id, byte[] buffer, short offset, short length) {

        //
        // PRE-CONDITIONS
        //

        // PRE-CONDITION 1
        // Only reference data associated with key references '80' and '81' specific to the PIV Card Application (i.e.,
        // local key reference) and the Global PIN with key reference '00' may be changed by the PIV Card
        // Application CHANGE REFERENCE DATA command.
        // Key reference '80' reference data shall be changed by the PIV Card Application CHANGE REFERENCE
        // DATA command. The ability to change reference data associated with key references '81' and '00' using
        // the PIV Card Application CHANGE REFERENCE DATA command is optional.


        // If key reference '81' is specified and the command is submitted over the contactless interface (including
        // SM or VCI), then the card command shall fail. If key reference '00' or '80' is specified and the command
        // is not submitted over either the contact interface or the VCI, then the card command shall fail. In each
        // case, the security status and the retry counter of the key reference shall remain unchanged.

        // NOTE: This is handled in the switch statement and is configurable at compile-time

        OwnerPIN pin = null;
        boolean pinAlways = false;
        byte intermediateLimit = (byte)0;

        switch (id) {

        case ID_KEY_GLOBAL_PIN:
            // Make sure FEATURE_PIN_GLOBAL_ENABLED is enabled (if you can't verify, you can't change either)
            if (!Config.FEATURE_PIN_GLOBAL_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

            // Make sure FEATURE_PIN_GLOBAL_CHANGE is enabled
            if (!Config.FEATURE_PIN_GLOBAL_CHANGE) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

            // Check whether we are allowed to operate over contactless if applicable
            if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            pin = cspPIV.globalPIN;
            intermediateLimit = Config.PIN_RETRIES_INTERMEDIATE;
            break;


        case ID_KEY_PIN:
            // Make sure FEATURE_PIN_CARD_ENABLED is enabled (if you can't verify, you can't change either)
            if (!Config.FEATURE_PIN_CARD_ENABLED) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

            // Check whether we are allowed to operate over contactless if applicable
            if (!Config.FEATURE_PIN_OVER_CONTACTLESS && cspPIV.getIsContactless()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            pin = cspPIV.cardPIN;
            intermediateLimit = Config.PIN_RETRIES_INTERMEDIATE;


            break;

        case ID_KEY_PUK:

            // Make sure FEATURE_PUK_CHANGE is enabled
            if (!Config.FEATURE_PUK_CHANGE) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

            // Check whether we are allowed to operate over contactless if applicable
            if (!Config.FEATURE_PUK_OVER_CONTACTLESS && cspPIV.getIsContactless()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            pin = cspPIV.cardPUK;
            intermediateLimit = Config.PUK_RETRIES_INTERMEDIATE;
            break;

        default:
            ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }


        // If the current value of the retry counter associated with the key reference is zero, then the reference data
        // associated with the key reference shall not be changed and the PIV Card Application shall return the
        // status word '69 83'.
        if (pin.getTriesRemaining() == (short)0) ISOException.throwIt(SW_OPERATION_BLOCKED);

        // If the command is submitted over the contactless interface (VCI) and the current value of the retry counter
        // associated with the key reference is at or below the issuer-specified intermediate retry value (see Section 3.2.1),
        // then the reference data associated with the key reference shall not be changed and the PIV Card Application shall
        // return the status word '69 83'.
        if (pin.getTriesRemaining() <= intermediateLimit) ISOException.throwIt(SW_OPERATION_BLOCKED);

        // If the authentication data in the command data field does not match the current value of the reference data
        // or if either the authentication data or the new reference data in the command data field of the command
        // does not satisfy the criteria in Section 2.4.3, the PIV Card Application shall not change the reference data
        // associated with the key reference and shall return either status word '6A 80' or '63 CX', with the following
        // restrictions.
        // SIMPLIFIED: If [Old PIN format is BAD] or [New PIN format is BAD] you can choose 6A80 or 63CX. We choose 6A80

        // If the authentication data in the command data field satisfies the criteria in Section 2.4.3 and
        // matches the current value of the reference data, but the new reference data in the command data field of
        // the command does not satisfy the criteria in Section 2.4.3, the PIV Card Application shall return status
        // word '6A 80'.
        // SIMPLIFIED: If [Old PIN is GOOD] but [New PIN format is BAD], use 6A80.

        // If the authentication data in the command data field does not match the current value of the
        // reference data, but both the authentication data and the new reference data in the command data field of
        // the command satisfy the criteria in Section 2.4.3, the PIV Card Application shall return status word
        // '63 CX'.
        // SIMPLIFIED: If [Old PIN format is GOOD] but [Old PIN is BAD], use 63CX and decrement.

        // If status word '6A 80' is returned, the security status and retry counter associated with the key
        // reference shall remain unchanged.9 If status word '63 CX' is returned, the security status of the key
        // reference shall be set to FALSE and the retry counter associated with the key reference shall be
        // decremented by one.

        // If the new reference data (PIN) in the command data field of the command does not satisfy the
        // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A 80'.

        // Verify the authentication reference data (old PIN) format
        if (!verifyPinFormat(id, buffer, offset, Config.PIN_LENGTH_MAX)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Verify the authentication reference data (old PIN) value
        if (!pin.check(buffer, offset, Config.PIN_LENGTH_MAX)) {
            // Return the number of retries remaining
            ISOException.throwIt((short)(SW_RETRIES_REMAINING | (short)pin.getTriesRemaining()));
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

        // If the card command succeeds, then the security status of the key reference shall be set to TRUE and the
        // retry counter associated with the key reference shall be set to the reset retry value associated with the key
        // reference.

        // STEP 1 - Update the PIN
        pin.update(buffer, offset, Config.PIN_LENGTH_MAX);

        // STEP 2 - Verify the new PIN, which will have the effect of setting it to TRUE and resetting the retry counter
        pin.check(buffer, offset, Config.PIN_LENGTH_MAX);

        // STEP 3 - Set the PIN ALWAYS flag as this is now verified
        if (pinAlways) cspPIV.setPINAlways(true);

        // Done
    }

    /**
     * The RESET RETRY COUNTER card command resets the retry counter of the PIN to its initial value and
     * changes the reference data. The command enables recovery of the PIV Card Application PIN in the case
     * that the cardholder has forgotten the PIV Card Application PIN.
     *
     * @param id The requested PIN reference
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA element
     * @param length The length of the CDATA element
     */
    public void resetRetryCounter(byte id, byte[] buffer, short offset, short length) {

        //
        // PRE-CONDITIONS
        //

        // PRE-CONDITION 1 - Check if we are permitted to use this command over the contactless interface
        //					 NOTE: We must check this for both the PIN and the PUK
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

        // PRE-CONDITION 3 - Check the PUK blocked status
        // If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall not be
        // reset and the PIV Card Application shall return the status word '69 83'.
        if (cspPIV.cardPUK.getTriesRemaining() == (short)0) ISOException.throwIt(SW_OPERATION_BLOCKED);

        // PRE-CONDITION 3 - Check the format of the NEW pin value
        // If the new reference data (PIN) in the command data field of the command does not satisfy the
        // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A 80'.
        if (!verifyPinFormat(id, buffer, (short)(offset + Config.PIN_LENGTH_MAX), Config.PIN_LENGTH_MAX)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // PRE-CONDITION 4 - Verify the PUK value
        // If the reset retry counter authentication data (PUK) in the command data field of the command does not
        // match reference data associated with the PUK, then the PIV Card Application shall return the status word
        // '63 CX'.
        if (!cspPIV.cardPUK.check(buffer, offset, Config.PIN_LENGTH_MAX)) {

            // Reset the PIN's security condition (see paragraph below for explanation)
            cspPIV.cardPIN.reset();

            // Check again if we are blocked
            if (cspPIV.cardPUK.getTriesRemaining() == (short)0) {
                ISOException.throwIt(SW_OPERATION_BLOCKED);
            } else {
                // Return the number of retries remaining
                ISOException.throwIt((short)(SW_RETRIES_REMAINING | (short)cspPIV.cardPUK.getTriesRemaining()));
            }
        }

        // If the reset retry counter authentication data (PUK) in the command data field of the command does not match
        // reference data associated with the PUK and the new reference data (PIN) in the command data field of the
        // command does not satisfy the criteria in Section 2.4.3, then the PIV Card Application shall return either
        // status word '6A 80' or '63 CX'. If the PIV Card Application returns status word '6A 80', then the retry
        // counter associated with the PIN shall not be reset, the security status of the PIN's key reference shall
        // remain unchanged, and the PUK's retry counter shall remain unchanged.11 If the PIV Card Application
        // returns status word '63 CX', then the retry counter associated with the PIN shall not be reset, the security
        // status of the PIN's key reference shall be set to FALSE, and the PUK's retry counter shall be
        // decremented by one.

        // NOTES:
        // - We implicitly decrement the PUK counter if the PUK is incorrect (63CX)
        // - Because we validate the PIN format before checking the PUK, we return WRONG DATA (6A80) in this case
        // - If the PUK check fails, we explicitly reset the PIN's security condition

        // If the card command succeeds, then the PIN's retry counter shall be set to its reset retry value. Optionally,
        // the PUK's retry counter may be set to its initial reset retry value. The security status of the PIN's key
        // reference shall not be changed.

        // NOTE: Since the PUK was verified, the OwnerPIN object automatically resets the PUK counter, which governs
        // 		 the above behaviour

        // Update, reset and unblock the PIN
		cspPIV.cardPIN.update(buffer, (short)(offset + Config.PIN_LENGTH_MAX), Config.PIN_LENGTH_MAX);
    }

    /**
     * Allows the applet to provide security state information to PIV for access control
     * @param isContactless Sets whether the current interface is contactless
     * @param isSecureChannel Sets whether the current command was issued over a GlobalPlatform Secure Channel
     */
    public void updateSecurityStatus(boolean isContactless, boolean isSecureChannel) {
        cspPIV.setIsContactless(isContactless);
        cspPIV.setIsSecureChannel(isSecureChannel);
    }

    /**
     * Clears any intermediate authentication status used by 'GENERAL AUTHENTICATE'
     */
    private void authenticateReset() {

        authenticationContext[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;
        authenticationContext[OFFSET_AUTH_ID] = (short)0;
        authenticationContext[OFFSET_AUTH_MECHANISM] = (short)0;
        Util.arrayFillNonAtomic(authenticationContext, OFFSET_AUTH_CHALLENGE, LENGTH_CHALLENGE, (byte)0);

    }

    /**
     * The GENERAL AUTHENTICATE card command performs a cryptographic operation, such as an authentication
     * protocol, using the data provided in the data field of the command and returns the result of
     * the cryptographic operation in the response data field.
     *
     * @param buffer The incoming APDU buffer
     * @param offset The offset of the CDATA element
     * @param length The length of the CDATA element
     * @return The length of the return data
     */
    public short generalAuthenticate(byte[] buffer, short offset, short length) {

        final byte CONST_TAG_TEMPLATE	= (byte)0x7C;
        final byte CONST_TAG_WITNESS 	= (byte)0x80;
        final byte CONST_TAG_CHALLENGE 	= (byte)0x81;
        final byte CONST_TAG_RESPONSE 	= (byte)0x82;

        //
        // COMMAND CHAIN HANDLING
        //

        // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
        // to of the chain to process, otherwise it will return the length of the large CDATA buffer
        length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short)0);

        // If the length is zero, just return so the caller can keep sending
        if (length == 0) return length;

        // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the original buffer
        // still contains the APDU header.

        // Set up our TLV reader
        tlvReader.init(scratch, (short)0, length);

        //
        // PRE-CONDITIONS
        //

        // PRE-CONDITION 1 - The key reference and mechanism must point to an existing key
        PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[ISO7816.OFFSET_P1]);
        if (key == null) {
            // If any key reference value is specified that is not supported by the card, the PIV Card Application
            // shall return the status word '6A 88'.
            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // PRE-CONDITION 2 - The key's value must have been set
        if (!key.isInitialised()) {
            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // PRE-CONDITION 3 - The access rules must be satisfied for the requested key
        if (!cspPIV.checkAccessModeObject(key)) {
            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // PRE-CONDITION 4 - The Dynamic Authentication Template tag must be present in the data
        if (!tlvReader.find(CONST_TAG_TEMPLATE)) {
            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Move into the content of the template
        tlvReader.moveInto();

        //
        // EXECUTION STEPS
        //

        //
        // STEP 1 - Traverse the TLV to determine what combination of elements exist
        //
        short challengeOffset = 0, witnessOffset = 0, responseOffset = 0;
        boolean challengeEmpty = false, witnessEmpty = false, responseEmpty = false;

        // Save the offset in the TLV object
        offset = tlvReader.getOffset();

        // Loop through all tags
        do {
            if (tlvReader.match(CONST_TAG_CHALLENGE)) {
                challengeOffset = tlvReader.getOffset();
                challengeEmpty = tlvReader.isNull();
            } else if (tlvReader.match(CONST_TAG_RESPONSE)) {
                responseOffset = tlvReader.getOffset();
                responseEmpty = tlvReader.isNull();
            } else if (tlvReader.match(CONST_TAG_WITNESS)) {
                witnessOffset = tlvReader.getOffset();
                witnessEmpty = tlvReader.isNull();
            } else {
                // We have come across an unknown tag value
                // TODO: We'll do nothing now until we know whether there are no edge cases where this is possible
            }
        } while(tlvReader.moveNext());

        // Restore the offset in the TLV object
        tlvReader.setOffset(offset);

        //
        // STEP 2 - Process the appropriate GENERAL AUTHENTICATE case
        //

        // Get our block length, which is used for the challenge size
        length = key.getBlockLength();

        //
        // NOTES:
        // There are 5 authentication cases that make up all of the GENERAL AUTHENTICATE functionality:
        // CASE 1 - If a RESPONSE is present but empty and a CHALLENGE is present with data, it is an INTERNAL AUTHENTICATE
        // CASE 2 - If a CHALLENGE is present but empty, it is an EXTERNAL AUTHENTICATE REQUEST
        // CASE 3 - If a RESPONSE is present with data, it is an EXTERNAL AUTHENTICATE RESPONSE
        // CASE 4 - If a WITNESS is present but empty, it is an MUTUAL AUTHENTICATE REQUEST
        // CASE 5 - If a WITNESS is present with data, it is an MUTUAL AUTHENTICATE RESPONSE
        // If any other tag combination is present in the first element of data, it is an invalid case.
        //

        //
        // CASE 1 - INTERNAL AUTHENTICATE
        // Authenticates the CARD to the CLIENT and is also used for KEY ESTABLISHMENT and
        // DIGITAL SIGNATURES.
        // Documented in SP800-73-4 Part 2 Appendix A.3
        //

        // > Client application sends a challenge to the PIV Card Application
        if ((challengeOffset != 0 && !challengeEmpty) && (responseOffset != 0 && responseEmpty)) {

            // Reset any other authentication intermediate state
            authenticateReset();

            // Validate that the key has the correct role for this operation
            if (!key.hasRole(PIVKeyObject.ROLE_AUTH_INTERNAL)) {
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Make sure that the incoming CHALLENGE data is equal to the block length
            tlvReader.setOffset(challengeOffset);
            if (tlvReader.getLength() != length) {
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // Write out the response TLV, passing through the block length as an indicative maximum
            tlvWriter.init(scratch, (short)0, length, CONST_TAG_TEMPLATE);

            // Create the RESPONSE tag
            tlvWriter.writeTag(CONST_TAG_RESPONSE);
            tlvWriter.writeLength(length);

            // Encrypt the CHALLENGE data and write it to the output buffer
            offset = tlvWriter.getOffset();
            offset += cspPIV.encrypt(key, scratch, tlvReader.getDataOffset(), length, scratch, offset);
            tlvWriter.setOffset(offset); // Update the TLV offset value

            // Finalise the TLV object and get the entire data object length
            length = tlvWriter.finish();

            // Set up the outgoing command chain
            chainBuffer.setOutgoing(scratch, (short)0, length, true);

            // Done, return the length of data we are sending
            return length;
        } // Continued below


        //
        // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
        // Authenticates the HOST to the CARD
        //

        // > Client application requests a challenge from the PIV Card Application.
        else if (challengeOffset != 0 && challengeEmpty) {

            // Reset any other authentication intermediate state
            authenticateReset();

            // Reset they key's security status
            key.resetSecurityStatus();

            // Validate that the key has the correct role for this operation
            if (!key.hasRole(PIVKeyObject.ROLE_AUTH_EXTERNAL)) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Write out the response TLV, passing through the block length as an indicative maximum
            tlvWriter.init(scratch, (short)0, length, CONST_TAG_TEMPLATE);

            // Create the CHALLENGE tag
            tlvWriter.writeTag(CONST_TAG_CHALLENGE);
            tlvWriter.writeLength(length);

            // Generate the CHALLENGE data and write it to the output buffer
            offset = tlvWriter.getOffset();
            cspPIV.generateRandom(scratch, offset, length);

            // Store the encrypted CHALLENGE in our context, for easy comparison later
            offset += cspPIV.encrypt(key, scratch, offset, length, authenticationContext, OFFSET_AUTH_CHALLENGE);

            tlvWriter.setOffset(offset); // Update the TLV offset value

            // Finalise the TLV object and get the entire data object length
            length = tlvWriter.finish();

            // Set our authentication state to EXTERNAL
            authenticationContext[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;
            authenticationContext[OFFSET_AUTH_ID] = key.getId();
            authenticationContext[OFFSET_AUTH_MECHANISM] = key.getMechanism();

            // Set up the outgoing command chain
            chainBuffer.setOutgoing(scratch, (short)0,  length, true);

            // Done, return the length of data we are sending
            return length;
        } // Continued below


        //
        // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
        //

        // > Client application requests a challenge from the PIV Card Application.
        else if (responseOffset != 0 && !responseEmpty) {

            // This command is only valid if the authentication state is EXTERNAL
            if (authenticationContext[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL) {
                // Invalid state for this command
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // This command is only valid if the key and mechanism have not changed
            if (authenticationContext[OFFSET_AUTH_ID] != key.getId() ||
                    authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
                // Invalid state for this command
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Verify that the RESPONSE tag length is the same as our block length
            tlvReader.setOffset(responseOffset);
            if (length != tlvReader.getLength()) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Compare the authentication statuses
            if (Util.arrayCompare(	scratch, tlvReader.getDataOffset(),
                                    authenticationContext, OFFSET_AUTH_CHALLENGE, length) != 0) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // We are now authenticated. Set the key's security status
            key.setSecurityStatus();

            // Reset our authentication state
            authenticateReset();

            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);

            // Done
            return (short)0;
        } // Continued below


        //
        // CASE 4 - MUTUAL AUTHENTICATE REQUEST
        //

        // > Client application requests a WITNESS from the PIV Card Application.
        else if (witnessOffset != 0 && witnessEmpty) {

            // Reset any other authentication intermediate state
            authenticateReset();

            // Reset they key security condition
            key.resetSecurityStatus();

            // Validate that the key has the correct role for this operation
            if (!key.hasRole(PIVKeyObject.ROLE_AUTH_EXTERNAL)) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // < PIV Card Application returns a WITNESS that is created by generating random
            //   data and encrypting it using the referenced key

            // Generate a block length worth of WITNESS data
            cspPIV.generateRandom(authenticationContext, OFFSET_AUTH_CHALLENGE, length);

            // Write out the response TLV, passing through the block length as an indicative maximum
            tlvWriter.init(scratch, (short)0, length, CONST_TAG_TEMPLATE);

            // Create the WITNESS tag
            tlvWriter.writeTag(CONST_TAG_WITNESS);
            tlvWriter.writeLength(length);

            // Encrypt the WITNESS data and write it to the output buffer
            offset = tlvWriter.getOffset();
            offset += cspPIV.encrypt(key, authenticationContext, OFFSET_AUTH_CHALLENGE, length, scratch, offset);
            tlvWriter.setOffset(offset); // Update the TLV offset value

            // Finalise the TLV object and get the entire data object length
            length = tlvWriter.finish();

            // Update our authentication status, id and mechanism
            authenticationContext[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
            authenticationContext[OFFSET_AUTH_ID] = key.getId();
            authenticationContext[OFFSET_AUTH_MECHANISM] = key.getMechanism();

            // Set up the outgoing command chain
            chainBuffer.setOutgoing(scratch, (short)0,  length, true);

            // Done, return the length of data we are sending
            return length;
        }


        //
        // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
        //

        // > Client application returns the decrypted witness referencing the original algorithm key reference
        else if (witnessOffset != 0 && !witnessEmpty && challengeOffset != 0 && !challengeEmpty) {

            // < PIV Card Application authenticates the client application by verifying the decrypted witness.

            // This command is only valid if the authentication state is EXTERNAL
            if (authenticationContext[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL) {
                // Invalid state for this command
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // This command is only valid if the key and mechanism have not changed
            if (authenticationContext[OFFSET_AUTH_ID] != key.getId() ||
                    authenticationContext[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
                // Invalid state for this command
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Verify that the WITNESS tag length is the same as our block length
            tlvReader.setOffset(witnessOffset);
            if (length != tlvReader.getLength()) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Compare the authentication statuses
            if (Util.arrayCompare(	scratch, tlvReader.getDataOffset(),
                                    authenticationContext, OFFSET_AUTH_CHALLENGE, length) != 0) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // NOTE: The WITNESS is now verified, on to the CHALLENGE

            // > Client application requests encryption of CHALLENGE data from the card using the same key.
            // Verify that the CHALLENGE tag length is the same as our block length
            tlvReader.setOffset(challengeOffset);
            length = tlvReader.getLength();
            if (key.getBlockLength() != length) {
                authenticateReset();
                cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Write out the response TLV, passing through the block length as an indicative maximum
            tlvWriter.init(scratch, (short)0, length, CONST_TAG_TEMPLATE);

            // Create the RESPONSE tag
            tlvWriter.writeTag(CONST_TAG_RESPONSE);
            tlvWriter.writeLength(length);

            // Encrypt the RESPONSE data and write it to the output buffer
            offset = tlvWriter.getOffset();
            offset += cspPIV.encrypt(key, scratch, tlvReader.getDataOffset(), key.getBlockLength(), scratch, offset);
            tlvWriter.setOffset(offset); // Update the TLV offset value

            // Finalise the TLV object and get the entire data object length
            length = tlvWriter.finish();

            // Set this key's authentication state
            key.setSecurityStatus();

            // Clear our authentication state
            authenticateReset();

            // Set up the outgoing command chain
            chainBuffer.setOutgoing(scratch, (short)0, length, true);

            // < PIV Card Application indicates successful authentication and sends back the encrypted challenge.
            return length;
        }

        //
        // INVALID CASE
        //
        else {
            authenticateReset();
            cspPIV.zeroise(scratch, (short)0, LENGTH_SCRATCH);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return (short)0; // Keep the compiler happy
        }
    }

    /**
     * The GENERATE ASYMMETRIC KEY PAIR card command initiates the generation and storing in the
     * card of the reference data of an asymmetric key pair, i.e., a public key and a private key.
     * The public key of the generated key pair is returned as the response to the command. If there
     * is reference data currently associated with the key reference, it is replaced in full by the
     * generated data.
     *
     * @param buffer The incoming APDU buffer
     * @param offset The offset of the CDATA element
     * @param length The length of the CDATA element
     * @return The length of the return data
     */
    public short generateAsymmetricKeyPair(byte[] buffer, short offset, short length) {

        final byte CONST_TAG_TEMPLATE		= (byte)0xAC;
        final byte CONST_TAG_MECHANISM		= (byte)0x80;
        final byte CONST_TAG_PARAMETER 		= (byte)0x81;

        final short CONST_TAG_RESPONSE		= (short)0x7F49;
        final byte CONST_TAG_MODULUS		= (byte)0x81; // RSA - The modulus
        final byte CONST_TAG_EXPONENT		= (byte)0x82; // RSA - The public exponent

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
        if (buffer[offset++] != (short)1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

		// PRE-CONDITION 5 - The 'MECHANISM' tag value must be one of the supported mechanisms
		//if (buffer[offset] != PIV.ID_ALG_RSA_1024 && buffer[offset] != PIV.ID_ALG_RSA_2048) {
			//ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		//}

        //
        // NOTE: We ignore the existence of the 'PARAMETER' tag, because according to SP800-78-4 the
        // RSA public exponent is now fixed to 65537 (Section 3.1 PIV Cryptographic Keys).
        // Since we don't support ECC algorithms yet, we have no other reason to read it.
        //

        // PRE-CONDITION 5 - The key reference and mechanism must point to an existing key
        PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[offset]);
        if (key == null) {			
			// NOTE: The error message we return here is different dependant on whether the key is bad (6A86),
			// 		 or the mechanism is bad (6A80) (See SP800-73-4 3.3.2 Generate Asymmetric Keypair). 
			if (!cspPIV.keyExists(buffer[ISO7816.OFFSET_P2])) {
				// The key reference is bad
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			} else {
				// The mechanism is bad
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);			
			}
        }

        // PRE-CONDITION 6 - The key must be an assymetric key (key pair)
        if (!(key instanceof PIVKeyObjectPKI)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        //
        // EXECUTION STEPS
        //

        // STEP 1 - Generate the key pair
        PIVKeyObjectPKI keyPair = (PIVKeyObjectPKI)key;
        keyPair.generate();

        // STEP 2 - Prepare the outgoing public key

        //
        // NOTE: We only support RSA keys in the current implementation so we're just direct casting.
        //		 Ideally we would use a factory to support multiple assymetric algorithms, but not today.
        //
        tlvWriter.init(scratch, (short)0, key.getKeyLength(), CONST_TAG_RESPONSE);

        // Modulus
        tlvWriter.writeTag(CONST_TAG_MODULUS);
        tlvWriter.writeLength(keyPair.getKeyLength());

        // The modulus data must be written manually because of how RSAPublicKey works
        offset = tlvWriter.getOffset();
        offset += keyPair.getModulus(scratch, offset);
        tlvWriter.setOffset(offset); // Move the current position forward

        // Exponent
        tlvWriter.writeTag(CONST_TAG_EXPONENT);
        tlvWriter.writeLength((short)3); // Hack! Why can't we get the size from RSAPublicKey?
        offset = tlvWriter.getOffset();
        offset += keyPair.getPublicExponent(scratch, offset);
        tlvWriter.setOffset(offset); // Move the current position forward

        length = tlvWriter.finish();
        chainBuffer.setOutgoing(scratch, (short)0, length, true);

        // Done, return the length of the object we are writing back
        return length;
    }


    /**
     * Performs data validation on an incoming PIN number to ensure that it conforms
     * to SP800-73-4 Part 2 - Authentication of an Individual
     * @param id The requested PIN reference to verify
     * @param buffer The buffer containing the PIN
     * @param offset The offset of the PIN data
     * @param length The length of the PIN data
     * @return True if the supplied PIN conforms to the format requirements
     */
    private boolean verifyPinFormat(byte id, byte[] buffer, short offset, short length) {

        final byte CONST_PAD = (byte)0xFF;

        // The pairing code shall be exactly 8 bytes in length and the PIV Card Application
        // PIN shall be between 6 and 8 bytes in length. If the actual length of PIV Card Application
        // PIN is less than 8 bytes it shall be padded to 8 bytes with 'FF' when presented to the card
        // command interface. The 'FF' padding bytes shall be appended to the actual value of the PIN.

        // NOTE: We define the minimum and maximum lengths in configuration, but only the max is checked
        //		 here because of the padding requirement
        if (length != Config.PIN_LENGTH_MAX) return false;

        // The PUK shall be 8 bytes in length, and may be any 8-byte binary value. That is, the bytes comprising the
        // PUK may have any value in the range 0x00-0xFF.
        // NOTE: This means there is no further validation to perform for the PUK
        if (id == ID_KEY_PUK) return true;

        // The bytes comprising the PIV Card Application PIN and pairing code shall be limited to values
        // 0x30-0x39, the ASCII values for the decimal digits '0'-'9'. For example,
        // 		+ Actual PIV Card Application PIN: '123456' or '31 32 33 34 35 36'
        //		+ Padded PIV Card Application PIN presented to the card command interface: '31 32 33 34 35 36 FF FF'

        // The PIV Card Application shall enforce the minimum length requirement of six bytes for the PIV Card
        // Application PIN (i.e., shall verify that at least the first six bytes of the value presented to the
        // card command interface are in the range 0x30-0x39) as well as the other formatting requirements
        // specified in this section.

        // If the Global PIN is used by the PIV Card Application, then the above encoding, length, padding, and
        // enforcement of minimum PIN length requirements for the PIV Card Application PIN shall apply to the
        // Global PIN.
        for (short i = 0; i < Config.PIN_LENGTH_MAX; i++) {

            if (i < Config.PIN_LENGTH_MIN) {
                // Must be between '0' and '9' only
                if (buffer[offset] < '0' || buffer[offset] >'9') return false;
            } else {
                // Must be between '0' and '9' OR the padding byte
                if ( (buffer[offset] < '0' || buffer[offset] >'9') && buffer[offset] != CONST_PAD) return false;
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
     * This is the administrative equivalent for the PUT DATA card and is intended for
     * use by Card Management Systems to generate the on-card file-system.
     *
     * @param buffer - The incoming APDU buffer
     * @param offset - The starting offset of the CDATA section
     * @param length - The length of the CDATA section
     */
    public void putDataAdmin(byte[] buffer, short offset, short length) {

        final byte CONST_TAG_COMMAND 			= (byte)0x30;
        final byte CONST_TAG_OPERATION 	 		= (byte)0x8A;
        final byte CONST_TAG_ID	 	 			= (byte)0x8B;
        final byte CONST_TAG_MODE_CONTACT		= (byte)0x8C;
        final byte CONST_TAG_MODE_CONTACTLESS	= (byte)0x8D;
        final byte CONST_TAG_KEY_MECHANISM 		= (byte)0x8E;
        final byte CONST_TAG_KEY_ROLE	 		= (byte)0x8F;

        final byte CONST_OP_DATA				= (byte)0x01;
        final byte CONST_OP_KEY					= (byte)0x02;

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
        length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short)0);

        // If the length is zero, just return so the caller can keep sending
        if (length == 0) return;

        // If we got this far, the scratch buffer now contains the incoming command. Keep in mind that
        // the original buffer still contains the APDU header.

        // Initialise our TLV reader
        tlvReader.init(scratch, (short)0, length);


        //
        // PRE-CONDITIONS
        //

        // PRE-CONDITION 1 - The 'COMMAND' constructed tag must be present
        if (!tlvReader.match(CONST_TAG_COMMAND)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        // Move into the constructed tag
        tlvReader.moveInto();

        // PRE-CONDITION 2 - The mandatory 'OPERATION' tag must be present with length 1
        if (!tlvReader.match(CONST_TAG_OPERATION)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        byte operation = tlvReader.toByte();

        // PRE-CONDITION 3 - The 'OPERATION' value must be set to the value CONST_OP_DATA or CONST_OP_KEY
        if (operation != CONST_OP_DATA && operation != CONST_OP_KEY) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        // Move to the next tag
        tlvReader.moveNext();

        // PRE-CONDITION 4 - The 'ID' value must be present with length 1
        if (!tlvReader.match(CONST_TAG_ID)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (tlvReader.getLength() != (short)1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte id = tlvReader.toByte();

        // Move to the next tag
        tlvReader.moveNext();

        // PRE-CONDITION 5 - The 'MODE CONTACT' value must be present with length 1
        if (!tlvReader.match(CONST_TAG_MODE_CONTACT)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (tlvReader.getLength() != (short)1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte modeContact = tlvReader.toByte();

        // Move to the next tag
        tlvReader.moveNext();

        // PRE-CONDITION 6 - The 'MODE CONTACTLESS' value must be present with length 1
        if (!tlvReader.match(CONST_TAG_MODE_CONTACTLESS)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (tlvReader.getLength() != (short)1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte modeContactless = tlvReader.toByte();

        byte keyMechanism = ID_ALG_DEFAULT;
        byte keyRole = PIVKeyObject.ROLE_NONE;

        // Move to the next tag
        tlvReader.moveNext();

        if (CONST_OP_KEY == operation) {

            // PRE-CONDITION 7a - If the operation is CONST_OP_KEY, then the 'KEY MECHANISM' tag
            //					 must be present with length 1
            if (!tlvReader.match(CONST_TAG_KEY_MECHANISM)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            if (tlvReader.getLength() != (short)1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            keyMechanism = tlvReader.toByte();

            // Move to the next tag
            tlvReader.moveNext();

            // PRE-CONDITION 8a - If the operation is CONST_OP_KEY, then the 'KEY ROLE' tag
            //					 must be present with length 1

            if (!tlvReader.match(CONST_TAG_KEY_ROLE)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            if (tlvReader.getLength() != (short)1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            keyRole = tlvReader.toByte();

            // PRE-CONDITION 9a - If 'OPERATION' is set to CONST_OP_KEY, the key referenced by the 'id' and
            //					  'mechanism' values must not already exist in the key store
            if (cspPIV.selectKey(id, keyMechanism) != null) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }

        } else { //(CONST_OP_DATA == operation)

            // PRE-CONDITION 7b - If 'OPERATION' is set to CONST_OP_DATA, the object referenced by 'id' value
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
            cspPIV.createKey(id, modeContact, modeContactless, keyMechanism, keyRole);
        }
    }

    /**
     * This method is the equivalent of the CHANGE REFERENCE DATA command, however it is intended to
     * operate on key references that are NOT listed in SP800-37-4. This is the primary method
     * by which administrative key references are updated and is intended to fill in the gap in PIV
     * that does not cover how pre-personalisation is implemented.
     *
     * @param id The target key / pin reference being changed
     * @param buffer The incoming APDU buffer
     * @param offset The starting offset of the CDATA section
     * @param length The length of the CDATA section
	 *
     * The main differences to CHANGE REFERENCE DATA are:
     * - It supports updating any key reference that is not covered by CHANGE REFERENCE DATA already
     * - It requires a global platform secure channel to be operating with the CEncDec attribute (encrypted)
     * - It does NOT require the old value to be supplied in order to change a key
     * - It also supports updating the PIN/PUK values, without requiring knowledge of the old value
     *
     */
    public void changeReferenceDataAdmin(byte id, byte[] buffer, short offset, short length) {

        final byte CONST_TAG_SEQUENCE			= (byte)0x30;
        final byte CONST_TAG_KEY				= (byte)0x80;
        final byte CONST_TAG_RSA_N				= (byte)0x81; // RSA Modulus
        final byte CONST_TAG_RSA_E				= (byte)0x82; // RSA Public Exponent
        final byte CONST_TAG_RSA_D				= (byte)0x83; // RSA Private Exponent

        // NOTE: Currently RSA CRT keys are not used, this is a placeholder
        //final short CONST_TAG_RSA_P				= (short)0x0084; // RSA Prime Exponent P
        //final short CONST_TAG_RSA_Q				= (short)0x0085; // RSA Prime Exponent Q
        //final short CONST_TAG_RSA_DP			= (short)0x0086; // RSA D mod P - 1
        //final short CONST_TAG_RSA_DQ			= (short)0x0087; // RSA D mod Q - 1
        //final short CONST_TAG_RSA_PQ			= (short)0x0088; // RSA Inverse Q

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
        length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, (short)0);

        // If the length is zero, just return so the caller can keep sending
        if (length == 0) return;

        // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the original buffer
        // still contains the APDU header.


        //
        // PIN cases
        //

        if (buffer[ISO7816.OFFSET_P2] == ID_KEY_PIN) {
            if (!verifyPinFormat(ID_KEY_PIN, scratch, (short)0, length)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // Update the PIN
            cspPIV.cardPIN.update(scratch, (short)0, (byte)length);

            // Done
            return;
        }

        if (buffer[ISO7816.OFFSET_P2] == ID_KEY_PUK) {
            if (!verifyPinFormat(ID_KEY_PUK, scratch, (short)0, length)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // Update the PUK
            cspPIV.cardPUK.update(scratch, (short)0, (byte)length);

            // Done
            return;
        }



        // PRE-CONDITION 1 - The key reference and mechanism must point to an existing key
        PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[ISO7816.OFFSET_P1]);
        if (key == null) {
            // If any key reference value is specified that is not supported by the card, the PIV Card Application
            // shall return the status word '6A 88'.
            ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }

        // Set up our TLV reader
        tlvReader.init(scratch, (short)0, length);

        // PRE-CONDITION 2 - The sequence tag must be present in the data
        if (!tlvReader.find(CONST_TAG_SEQUENCE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Move to the child tag
        tlvReader.moveInto();

        //
        // EXECUTION STEPS
        //
        
        key.updateElement(tlvReader.getTag(), scratch, tlvReader.getDataOffset(), tlvReader.getLength());
    }

    /**
     * Searches for a data object within the local data store
     * @param id The data object to find
     */
    private PIVDataObject findDataObject(byte id) {

        PIVDataObject data = firstDataObject;

        // Traverse the linked list
        while (data != null) {
            if (data.match(id)) {
                return data;
            };

            data = (PIVDataObject)data.nextObject;
        }

        return null;

    }

    /**
     * Adds a data object to the data store
     * @param The id of the data object to create (just the LSB)
     * @param The contact Access Mode control flags
     * @param The contactless Access Mode control flags
     */
    private void createDataObject(byte id, byte modeContact, byte modeContactess) {

        final byte ID_DISCOVERY = (byte)0x7E;

        // Create our new key
        PIVDataObject data = new PIVDataObject(id, modeContact, modeContactess);

        // Check if this is the first key added
        if (firstDataObject == null) {
            firstDataObject = data;
            return;
        }

        // Find the last data object in the linked list
        PIVObject last = firstDataObject;
        while (last.nextObject != null) {
            last = last.nextObject;
        }

        // Assign the next object
        last.nextObject = data;


        //
        // SPECIAL OBJECT - Discovery Data
        // This automatically populates the discovery object if it is added, based on our compiled
        // configuration
        //
        if (Config.FEATURE_DISCOVERY_OBJECT_DEFAULT && ID_DISCOVERY == id) {

            data.allocate((short)Config.DEFAULT_DISCOVERY.length);

            Util.arrayCopyNonAtomic(Config.DEFAULT_DISCOVERY, (short)0,
                                    data.content,
                                    (short)0,
                                    (short)Config.DEFAULT_DISCOVERY.length);
        }
    }
}