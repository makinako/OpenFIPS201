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
import org.globalplatform.SecureChannel;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * The PIVAPDU class abstracts the complexities of handling APDU chaining and secure messaging
 * for PIV applications. It manages an internal transient buffer to support reading and writing
 * data larger than a single APDU frame while automating state management and transaction handling.
 * 
 * <p>This class supports two primary modes:
 * <ul>
 *   <li><b>Incoming APDU chaining:</b> It assembles command data received in multiple frames, either
 *       into an internal buffer or into an externally supplied object. Upon completion, it performs
 *       any necessary secure messaging unwrapping and marks the command as complete.</li>
 *   <li><b>Outgoing APDU chaining:</b> It segments response data to be sent via subsequent GET RESPONSE
 *       commands. The class tracks how much data remains and automatically adjusts the outgoing state
 *       until the entire response has been transmitted.</li>
 * </ul>
 *
 * <p>In addition, the class integrates with GlobalPlatform secure messaging (both SCP and PIVSM)
 * to handle APDU unwrapping. It provides helper methods to access APDU header fields, the data buffer,
 * and to determine the secure channel used.
 *
 * <p>State transitions are automatically managed:
 * <ul>
 *   <li>Incoming states progress from STATE_NONE -> STATE_INCOMING_APDU -> (optionally) STATE_INCOMING_OBJECT 
 *       -> STATE_INCOMING_APDU_COMPLETE or STATE_INCOMING_OBJECT_COMPLETE, depending on configuration and
 *       whether the data is chained.</li>
 *   <li>Outgoing states are initiated via setOutgoingAPDU/Object (STATE_OUTGOING_SET) and progress through
 *       STATE_OUTGOING as frames are sent, with a final reset to STATE_NONE upon completion.</li>
 * </ul>
 *
 * <p>Any protocol violation or error during processing triggers a reset of the internal state and
 * clears the data buffer to ensure data integrity.
 *
 * @see APDU
 * @see ISO7816
 * @see GPSystem
 * @see SecureChannel
 */
final class PIVAPDU {

  //
  // Constants
  //

  // The maximum length that can be contained in a single ISO7816 R-APDU data section (short case)
  private static final short MAX_RAPDU_LENGTH = (short) 256;

  // This CLA mask strips the chaining bit (0x10)
  private static final byte MASK_CLA_CHAINING = (byte) 0x10;

  // The current APDU was not processed by any secure channel
  static final byte SECURE_CHANNEL_NONE = (byte) 0x00;

  // The current APDU was processed by Global Platform SCP
  static final byte SECURE_CHANNEL_SCP = (byte) 0x04;

  // The current APDU was processed by PIV Secure Messaging
  static final byte SECURE_CHANNEL_PIVSM = (byte) 0x0C;
  //
  // STATE TRACKING
  //

  // The internal buffer is empty and no outstanding read or write operation exists
  static final short STATE_NONE = (short) 0;

  // A chained response operation is ongoing from either of an internal or external buffer
  static final short STATE_OUTGOING = (short) 1;

  // A chained command APDU is in progress, writing to the internal buffer
  static final short STATE_INCOMING_APDU = (short) 2;

  // An incoming APDU is completed and ready for processing
  static final short STATE_INCOMING_APDU_COMPLETE = (short) 3;

  // A chained command APDU is in progress, writing to an externally supplied buffer
  static final short STATE_INCOMING_OBJECT = (short) 4;

  // An incoming Object is completed and no further processing required
  static final short STATE_INCOMING_OBJECT_COMPLETE = (short) 5;

  // The chain state
  private static final short CONTEXT_STATE = (short) 0;

  // The current offset in the data buffer
  private static final short CONTEXT_OFFSET = (short) 1;

  // The total length of the data buffer
  private static final short CONTEXT_LENGTH = (short) 2;

  // The number of remaining bytes to read or write
  private static final short CONTEXT_REMAINING = (short) 3;

  // Indicates whether the chain is operating inside a transaction
  private static final short CONTEXT_TRANSACTION = (short) 4;

  // Indicates by which method the current APDU is wrapped, if any
  private static final short CONTEXT_SECURE_CHANNEL = (short) 5;

  // Indicates what response status is expected to be returned
  private static final short CONTEXT_RESPONSE_STATUS = (short) 6;

  // Total length of the context transient object
  private static final short LENGTH_CONTEXT = (short) 7;

  // A pointer to our read/write data buffer
  private static final short CONTEXT_PTR_BUFFER = (short) 0;

  // A pointer to our object container if writing an object
  private static final short CONTEXT_PTR_CONTAINER = (short) 1;

  // Total length of the context pointers object
  private static final short LENGTH_CONTEXT_PTR = (short) 2;

  // The length of the APDU header at the start of the data buffer. Used to get the start of the 
  // CDATA.
  static final short LENGTH_HEADER = (short) 4;

  // TRANSIENT - The internal memory buffer to store all incoming and outgoing APDU's data
  private final byte[] dataBuffer;

  // REFERENCE - Secure Messaging Providers
  private final ChannelSCP channelSCP;
  private final ChannelPIVSM channelPIVSM;

  // TRANSIENT - Holds a pointer to the supplied buffer to populate
  private final Object[] contextPtrs;

  // TRANSIENT - Holds context information about the current chain
  private final short[] context;

  PIVAPDU(ChannelSCP channelSCP, ChannelPIVSM channelPIVSM) {
    dataBuffer = JCSystem.makeTransientByteArray(Config.LENGTH_PIV_APDU_BUFFER, JCSystem.CLEAR_ON_DESELECT);
    contextPtrs = JCSystem.makeTransientObjectArray(LENGTH_CONTEXT_PTR, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);

    this.channelPIVSM = channelPIVSM;
    this.channelSCP = channelSCP;

    reset();
  }

  /**
   * Returns a reference to the internal APDU buffer
   *
   * @return the reference to the internal APDU buffer
   */
  byte[] getData() {
    return dataBuffer;
  }

  byte getCLA() {
    return dataBuffer[ISO7816.OFFSET_CLA];
  }

  byte getINS() {
    return dataBuffer[ISO7816.OFFSET_INS];
  }

  byte getP1() {
    return dataBuffer[ISO7816.OFFSET_P1];
  }

  byte getP2() {
    return dataBuffer[ISO7816.OFFSET_P2];
  }

  /**
   * Returns the number of bytes written to the internal APDU buffer
   *
   * @return The number of bytes written to the internal APDU buffer
   */
  short getDataLength() {
    return context[CONTEXT_LENGTH];
  }

  /**
   * Returns the offset where the CDATA section begins
   *
   * @return The offset where the CDATA section begins
   */
  short getDataOffset() {
    return LENGTH_HEADER;
  }

  boolean isCompleteCommand() {
    return context[CONTEXT_STATE] == STATE_INCOMING_APDU_COMPLETE
        || context[CONTEXT_STATE] == STATE_INCOMING_OBJECT_COMPLETE;
  }

  /**
   * Returns the current processing state
   *
   * @return The current processing state
   */
  short getState() {
    return context[CONTEXT_STATE];
  }

  /**
   * Configures the PIVBuffer class to process a chain of incoming data directly to an object
   *
   * @param destination The buffer to write data to
   * @param offset The starting offset of the data to write to
   * @param length The length to expect to be written
   * @param atomic If true, this operation will be conducted inside a transaction
   */
  void setIncomingObject(PIVContainer container, short length, boolean atomic) {

    //
    // PRE-CONDITIONS
    // 

    // PRE-CONDITION: The first frame of the APDU must be already processed
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU && context[CONTEXT_STATE] != STATE_INCOMING_APDU_COMPLETE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // EXECUTION
    //

    // Allocate, this will return the internal buffer
    contextPtrs[CONTEXT_PTR_CONTAINER] = container;
    contextPtrs[CONTEXT_PTR_BUFFER] = container.allocate(length);

    context[CONTEXT_STATE] = STATE_INCOMING_OBJECT;
    context[CONTEXT_OFFSET] = Constants.ZERO_SHORT;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = Constants.ZERO_SHORT;

    if (atomic) {
      Platform.beginTransaction();
      context[CONTEXT_TRANSACTION] = Constants.TRUE_SHORT;
    } else {
      context[CONTEXT_TRANSACTION] = Constants.FALSE_SHORT;
    }
  }

  /**
   * Configures the PIVBuffer class to process a response with no data.
   */
  void setOutgoingStatus(short status) {

    //
    // PRE-CONDITIONS
    // 

    // PRE-CONDITION: The first frame of the APDU must be already processed
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU_COMPLETE && context[CONTEXT_STATE] != STATE_OUTGOING) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // EXECUTION
    //

    // We set the context buffer to null to prevent an unintended access
    contextPtrs[CONTEXT_PTR_BUFFER] = null;

    context[CONTEXT_STATE] = STATE_OUTGOING;
    context[CONTEXT_OFFSET] = 0;
    context[CONTEXT_REMAINING] = 0;
    context[CONTEXT_LENGTH] = 0;
    context[CONTEXT_TRANSACTION] = Constants.FALSE_SHORT;
    context[CONTEXT_RESPONSE_STATUS] = status;

    // NOTE: We don't touch CONTEXT_SECURE_CHANNEL here to preserve it for response wrapping
  }

  /**
   * Configures the PIVBuffer class to process a stream of outgoing data which will be retrieved by
   * subsequent GET RESPONSE commands
   *
   * @param offset The starting offset of the internal buffer to read from
   * @param length The total number of bytes to send
   */
  void setOutgoingAPDU(short offset, short length) {

    //
    // PRE-CONDITIONS
    // 

    // PRE-CONDITION: The first frame of the APDU must be already processed
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU_COMPLETE && context[CONTEXT_STATE] != STATE_OUTGOING) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // EXECUTION
    //

    // Set the container pointer to null so the internal buffer is used
    contextPtrs[CONTEXT_PTR_BUFFER] = dataBuffer;

    context[CONTEXT_STATE] = STATE_OUTGOING;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;
    context[CONTEXT_TRANSACTION] = Constants.FALSE_SHORT;
    context[CONTEXT_RESPONSE_STATUS] = ISO7816.SW_NO_ERROR;

    // NOTE: We don't touch CONTEXT_SECURE_CHANNEL here to preserve it for response wrapping
  }

  /**
   * Configures the PIVBuffer class to process a stream of outgoing data which will be retrieved by
   * subsequent GET RESPONSE commands
   *
   * @param buffer the buffer to read data from
   * @param offset The starting offset of the data to read from
   * @param length The total number of bytes to read
   */
  void setOutgoingObject(byte[] destination, short offset, short length) {

    //
    // PRE-CONDITIONS
    // 

    // PRE-CONDITION: The first frame of the APDU must be already processed
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU_COMPLETE && context[CONTEXT_STATE] != STATE_OUTGOING) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // EXECUTION
    //

    contextPtrs[CONTEXT_PTR_BUFFER] = destination;

    context[CONTEXT_STATE] = STATE_OUTGOING;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;
    context[CONTEXT_TRANSACTION] = Constants.FALSE_SHORT;
    context[CONTEXT_RESPONSE_STATUS] = ISO7816.SW_NO_ERROR;

    // NOTE: We don't touch CONTEXT_SECURE_CHANNEL here to preserve it for response wrapping
  }

  /**
   * Reads an incoming APDU, including unwrapping and chained command handling and writes the result
   * to either the internal transient buffer or directly to an object, depending on how this class
   * instance was configured.
   *
   * @param apdu The incoming command APDU (or part thereof) to process
   * @param apduCase Indicates the expected APDU case, which governs management of incoming data
   * @return The number of bytes in the command data if complete, otherwise zero to indicate there
   *     is more to come NOTE: The destination will contain only the command data of the APDU, not
   *     the header.
   */
  short processIncomingAPDU(APDU apdu, short offset, short length) throws ISOException {
    //
    // STATE MANAGEMENT
    //

    // Ensure that the method is called in a suitable state
    switch (context[CONTEXT_STATE]) {

    // RULE: If processIncoming() is called when there is response data to be processed, clear it
    // RULE: If processIncoming() is called when there is a previously completed APDU, clear it
    case STATE_OUTGOING:
    case STATE_INCOMING_APDU_COMPLETE:
    case STATE_INCOMING_OBJECT_COMPLETE:
      reset();
      break;

    case STATE_NONE:
    case STATE_INCOMING_APDU:
    case STATE_INCOMING_OBJECT:
      // Nothing to do, these are the states managed by this method
      break;

    default:
      // Insane state, should never be reached
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      break;
    }

    byte[] apduBuffer = apdu.getBuffer();

    // NOTE: Strip the chaining bit from the CLA. We retain the Secure Messaging bits here to 
    // ensure all parts of a chain retain the same level of secure messaging.
    final byte CLA = (byte) (apduBuffer[ISO7816.OFFSET_CLA] & ~MASK_CLA_CHAINING);

    //
    // STATE_NONE --> STATE_INCOMING_APDU
    // 
    // If our state is NONE, we default to an incoming APDU and write the first/only part to the
    // internal buffer
    if (context[CONTEXT_STATE] == STATE_NONE) {
      contextPtrs[CONTEXT_PTR_BUFFER] = dataBuffer;
      context[CONTEXT_STATE] = STATE_INCOMING_APDU;

      // Write the 4 header bytes (CLA/INS/P1/P2)
      Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CLA, dataBuffer, Constants.ZERO_SHORT, LENGTH_HEADER);

      // Replace the CLA byte with our stripped version
      dataBuffer[Constants.ZERO_SHORT] = CLA;

      context[CONTEXT_LENGTH] = 0;
      context[CONTEXT_OFFSET] = LENGTH_HEADER;
      context[CONTEXT_REMAINING] = (short) (Config.LENGTH_PIV_APDU_BUFFER - LENGTH_HEADER);
    } else {
      //
      // STATE_INCOMING_APDU OR STATE_INCOMING_OBJECT
      // 

      // Validate that we are chaining for the correct command
      if (CLA != getCLA() || apduBuffer[ISO7816.OFFSET_INS] != getINS() || apduBuffer[ISO7816.OFFSET_P1] != getP1()
          || apduBuffer[ISO7816.OFFSET_P2] != getP2()) {
        //
        // From ISO7816 5.1.1.1:
        // "This document specifies the card behaviour only in the case where, once initiated, a
        // chain is terminated before initiating a command-response pair not part of the chain.
        // Otherwise the card behaviour is not specified.
        //
        // Unlike GET RESPONSE interruption, command chain interruption doesn't have a clear purpose
        // in this applet, so we will throw an error.
        reset();
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }
    }

    // If this APDU is wrapped in PIV-SM, check the command is supported
    if (ChannelPIVSM.isWrapped(getCLA()) && !ChannelPIVSM.isSupportedCommand(getINS())) {
      channelPIVSM.reset();
      
      // PIV Test Runner compatibility check
      // For the 'PUT DATA' command only, the error status is expected to be SW_FUNC_NOT_SUPPORTED!
      if (getINS() == OpenFIPS201.INS_PIV_PUT_DATA) {
        reset();
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);        
      } else {
        reset();
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);        
      }
    }

    // Process GP Secure Channel Unwrapping
    // NOTES: 
    // - SCP unwrapping is per-APDU, which means we call this [n] times for an [n] part command. 
    // - Unwrapping is in-place and writes back to the same location
    // - If the channel is not established, nothing will happen
    // - Only secure messaging wrapped under SCP will be processed by this, PIV SM will be ignored.
    if (ChannelSCP.isSecureChannel(CLA)) {
      // Unwrap, including the header and removing it afterwards from the length
      try {
        length += ISO7816.OFFSET_CDATA;
        length = channelSCP.unwrap(apduBuffer, ISO7816.OFFSET_CLA, length);
        length -= ISO7816.OFFSET_CDATA;
      } catch (ISOException ex) {
        reset();
        channelSCP.reset();
        throw ex;
      } catch (Exception ex) {
        reset();
        channelSCP.reset();
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }

      // Since we have successfully unwrapped using a secure channel, this is now considered
      // an administrative command. If it is incomplete, all subsequent parts of the chain
      // will be forced through unwrapping also and a failure will reset this status.
      context[CONTEXT_SECURE_CHANNEL] = SECURE_CHANNEL_SCP;
    }

    // NOTE: We should now only be in one of the following states:
    // STATE_INCOMING_APDU
    // STATE_INCOMING_OBJECT

    // Implement the chaining and non-chaining cases here for both APDU and object
    // IN_APDU non chaining means state will be set to APDU_COMPLETE
    // IN_OBJ non chaining means stated will be set to NONE

    return copyIncomingBytes(apduBuffer, offset, length, apdu.isCommandChainingCLA());
  }

  short processIncomingObject(short offset, short length, boolean isChained) throws ISOException {
    // PRE-CONDITION: We can only enter this stage from STATE_INCOMING_OBJECT, which must have
    // been previously called to write the first APDU frame into the local buffer
    if (context[CONTEXT_STATE] != STATE_INCOMING_OBJECT) {
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // This method just copies the already processed first frame without re-processing/unwrapping
    return copyIncomingBytes(dataBuffer, offset, length, isChained);
  }

  private short copyIncomingBytes(byte[] src, short offset, short length, boolean isChained) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: We must be processing an incoming APDU or OBJECT
    switch (context[CONTEXT_STATE]) {

    case STATE_INCOMING_APDU:
      break;

    case STATE_INCOMING_OBJECT:
      // PRE-CONDITION: For incoming objects, the last frame must contain EXACTLY the remaining bytes
      if (!isChained && length != context[CONTEXT_REMAINING]) {
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      break;

    default:
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    }

    byte[] dest = (byte[]) contextPtrs[CONTEXT_PTR_BUFFER];

    // PRE-CONDITION: Our incoming frame must not exceed the destination capacity
    if (length > context[CONTEXT_REMAINING]) {
      reset();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    //
    // Execution
    //

    // Copy the buffer to the destination and we are done
    try {
      if (context[CONTEXT_TRANSACTION] == Constants.TRUE_SHORT) {
        Util.arrayCopy(src, offset, dest, context[CONTEXT_OFFSET], length);
      } else {
        Util.arrayCopyNonAtomic(src, offset, dest, context[CONTEXT_OFFSET], length);
      }
      context[CONTEXT_OFFSET] += length;
      context[CONTEXT_LENGTH] += length;
      context[CONTEXT_REMAINING] -= length;
    } catch (Exception ex) {
      // Buffer overrun or unexpected writing error
      reset();
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }

    //
    // Process the final frame if applicable
    //
    if (!isChained) {
      if (context[CONTEXT_STATE] == STATE_INCOMING_OBJECT) {
        // We have received the entire expected object length, we are done writing and must now
        // 'finalise' the container
        PIVContainer container = (PIVContainer) (contextPtrs[CONTEXT_PTR_CONTAINER]);
        container.finalise();

        if (Constants.TRUE_SHORT == context[CONTEXT_TRANSACTION]) {
          Platform.commitTransaction();
        }
        context[CONTEXT_STATE] = STATE_INCOMING_OBJECT_COMPLETE;
      } else { // context[CONTEXT_STATE] == STATE_INCOMING_APDU
        // Process PIV Secure Messaging
        // NOTES: 
        // - PIV unwrapping is per-command, which means we call this once for the entire command. 
        // - If the channel is not established, nothing will happen
        // - Only secure messaging wrapped under PIVSM will be processed by this, SCP will be ignored.
        // - PIVSM does NOT confer administrative rights
        if (ChannelPIVSM.isWrapped(getCLA())) {
          try {
            context[CONTEXT_LENGTH] = channelPIVSM.unwrap(this);
            context[CONTEXT_SECURE_CHANNEL] = SECURE_CHANNEL_PIVSM;
          } catch (ISOException ex) {
            // Any error that occurs during PIVSM must reset the session
            reset();
            channelPIVSM.reset();
            throw ex;
          } catch (Exception ex) {
            // Any error that occurs during PIVSM must reset the session
            reset();
            channelPIVSM.reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
          }
        }

        context[CONTEXT_STATE] = STATE_INCOMING_APDU_COMPLETE;
      }
    }

    // In all normal circumstances, we return the length read (even if not complete) 
    return context[CONTEXT_LENGTH]; // Return the # of bytes read so far
  }

  /**
   * Starts or continues processing for an outgoing buffer being transmitted to the host
   *
   * @param apdu The current APDU buffer to transmit with
   */
  void processOutgoing(APDU apdu) throws ISOException {
    //
    // This is intended to be only executed immediately after setOutgoing, or when a GET RESPONSE is 
    // explicitly requested by the host (which should only be in .
    //
    // --------------------------------------------------------------------------------------------
    //                      
    // --------------------------------------------------------------------------------------------
    // STATE_NONE
    // STATE_INCOMING_APDU
    // STATE_INCOMING_APDU_COMPLETE
    // STATE_INCOMING_OBJECT
    // STATE_INCOMING_OBJECT_COMPLETE
    // STATE_OUTGOING
    //
    // This will throw an exception if it is in the wrong state because it indicates the user 
    // requested more data intentionally when there was none to provide.
    //
    // The NIST SP-33 reference database uses ID One PIV 2.4 cards and this implementation
    // returns 9000 if you try to issue a GET RESPONSE when there was nothing to get. Yubikey
    // however returns SW_WRONG_DATA. We believe Yubikey is handling it the more correct way and
    // so we will raise an error unless someone out there provides a compelling reason not to.
    //

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: We must be in the STATE_OUTGOING state
    if (context[CONTEXT_STATE] != STATE_OUTGOING) {
      // Invalid State
      reset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    byte[] apduBuffer = apdu.getBuffer();

    // Transmit the next frame up to a maximum of 'NE' bytes
    short ne = apdu.setOutgoing();

    // If LE is 0 then the host did not supply one; assume maximum of 256.
    if (ne == 0) {
      ne = MAX_RAPDU_LENGTH;
    }

    byte[] data = (byte[]) contextPtrs[CONTEXT_PTR_BUFFER];

    // Track both the data read from the buffer and the data written to the output
    short inLength = (context[CONTEXT_REMAINING] > ne) ? ne : context[CONTEXT_REMAINING];
    short outLength = inLength;
    short status = context[CONTEXT_RESPONSE_STATUS];

    switch (context[CONTEXT_SECURE_CHANNEL]) {

    case SECURE_CHANNEL_NONE:
      //
      // PLAINTEXT: Send the data directly from the source buffer up to the maximum permitted
      //
      apdu.setOutgoingLength(outLength);
      if (inLength > 0) {
        apdu.sendBytesLong(data, context[CONTEXT_OFFSET], outLength);
        context[CONTEXT_REMAINING] -= inLength;
        context[CONTEXT_OFFSET] += inLength;
      }

      // If we have nothing left to send, clear our context and return 9000
      if (context[CONTEXT_REMAINING] > 0) {
        status = ISO7816.SW_BYTES_REMAINING_00;
        status |= (context[CONTEXT_REMAINING] > (short) 0x00FF) ? (short) 0x00FF : context[CONTEXT_REMAINING];
      }
      break;

    case SECURE_CHANNEL_SCP:
      //
      // SCP: If SCP && RMAC/RENCRYPTION is enabled, wrap it first
      // NOTE: We limit our response data to the maximum supported depending on which mode is enabled
      //

      // If response wrapping is not required, just treat it as plaintext
      if (channelSCP.isResponseWrapped()) {
        short limit = channelSCP.getMaxWrapLength();
        if (inLength > limit) {
          inLength = limit;
        }
        // Figure out what status we intend to return first so we can include it in the wrap data
        if ((short) (context[CONTEXT_REMAINING] - inLength) > 0) {
          status = ISO7816.SW_BYTES_REMAINING_00;
          status |= (context[CONTEXT_REMAINING] > (short) 0x00FF) ? (short) 0x00FF : context[CONTEXT_REMAINING];
        }

        // Copy the data (if any) and the status bytes (they will be removed later) to the output
        if (inLength > 0) {
          Util.arrayCopyNonAtomic(data, context[CONTEXT_OFFSET], apduBuffer, Constants.ZERO_SHORT, inLength);
        }
        Util.setShort(apduBuffer, inLength, status);

        // Call wrap, passing through the input length and additional 2 status bytes
        try {
          outLength = channelSCP.wrap(apduBuffer, Constants.ZERO_SHORT, (short) (inLength + 2));
        } catch (ISOException ex) {
          reset();
          channelSCP.reset();
          throw ex;
        } catch (Exception ex) {
          reset();
          channelSCP.reset();
          ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        apdu.setOutgoingLength(outLength);
        apdu.sendBytes(Constants.ZERO_SHORT, outLength);
      } else {
        // Same as plaintext
        apdu.setOutgoingLength(outLength);
        if (outLength > 0) {
          apdu.sendBytesLong(data, context[CONTEXT_OFFSET], outLength);
        }
      }
      
      context[CONTEXT_REMAINING] -= inLength;
      context[CONTEXT_OFFSET] += inLength;

      // If we have nothing left to send, clear our context and return 9000
      if (context[CONTEXT_REMAINING] > 0) {
        status = ISO7816.SW_BYTES_REMAINING_00;
        status |= (context[CONTEXT_REMAINING] > (short) 0x00FF) ? (short) 0x00FF : context[CONTEXT_REMAINING];
      }
      break;

    case SECURE_CHANNEL_PIVSM:
      //
      // PIVSM: All wrapped commands require a wrapped response, except when acknowledging chaining
      // We call the wrap method, reading from the data and writing the result out to the APDU 
      // buffer.
      // NOTE:
      // - For the length, we pass through the remaining bytes so that on the first call, the 
      //   wrap() method knows the entire amount of data to encipher and can calculate padding.
      // - In subsequent calls, wrap() will track the remaining amount.
      // - This method returns the # of bytes written to the OUTPUT buffer, not read from the INPUT

      try {
        outLength = channelPIVSM.wrap(data, context[CONTEXT_OFFSET], context[CONTEXT_REMAINING], apduBuffer,
            Constants.ZERO_SHORT, ne, status);
      } catch (ISOException ex) {
        // Any error that occurs during PIVSM must reset the session
        reset();
        channelPIVSM.reset();
        throw ex;
      } catch (Exception ex) {
        // Any error that occurs during PIVSM must reset the session
        reset();
        channelPIVSM.reset();
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      apdu.setOutgoingLength(outLength);
      if (outLength > 0) {
        apdu.sendBytes(Constants.ZERO_SHORT, outLength);        
      }

      // Request how many INPUT bytes were used in the call to wrap()
      inLength = channelPIVSM.getLastBytesWrapped();

      context[CONTEXT_REMAINING] -= inLength;
      context[CONTEXT_OFFSET] += inLength;

      // Figure out what status we intend to return first so we can include it in the wrap
      short bytesRemaining = channelPIVSM.getRemainingBytesWrapped();
      if (bytesRemaining == 0) {
        // We already wrapped the real status response so we just return 9000 no matter what
        status = ISO7816.SW_NO_ERROR;
      } else {
        status = ISO7816.SW_BYTES_REMAINING_00;
        status |= (bytesRemaining > (short) 0x00FF) ? (short) 0x00FF : bytesRemaining;
      }
      break;

    default:
      // Insane condition
      reset();
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      break;
    }

    // If we have remaining bytes, status will indicate this so we throw it
    if (status != ISO7816.SW_NO_ERROR) {
      ISOException.throwIt(status);
    } else {
      // Done, no bytes remaining
      reset();
    }
  }

  /** Resets the PIVBuffer and clears any internal buffer and state tracking values */
  void reset() {
    // Burn them... Burn them all
    context[CONTEXT_SECURE_CHANNEL] = SECURE_CHANNEL_NONE;
    context[CONTEXT_OFFSET] = Constants.ZERO_SHORT;
    context[CONTEXT_REMAINING] = Constants.ZERO_SHORT;
    context[CONTEXT_LENGTH] = Constants.ZERO_SHORT;
    context[CONTEXT_TRANSACTION] = Constants.FALSE_SHORT;
    context[CONTEXT_STATE] = STATE_NONE;
    context[CONTEXT_RESPONSE_STATUS] = ISO7816.SW_NO_ERROR;

    // The internal buffer is reset to null by default to prevent accidental use without setup
    contextPtrs[CONTEXT_PTR_BUFFER] = null;
    contextPtrs[CONTEXT_PTR_CONTAINER] = null;

    // Have we been asked to conduct this in a transaction? If so abort it automatically
    if (Constants.TRUE_SHORT == context[CONTEXT_TRANSACTION]) {
      Platform.abortTransaction();
    }

    // Zeroise the internal buffer
    Platform.zeroise(dataBuffer, Constants.ZERO_SHORT, Config.LENGTH_PIV_APDU_BUFFER);
  }

  /**
   * Returns true if the currently defined channel is considered administrative. Note that this does
   * not indicate whether the command is complete, which may be required to validate the
   * administrative status (integrity protection may not be checked until it is complete).
   *
   * @return
   */
  byte getSecureChannel() {
    return (byte) context[CONTEXT_SECURE_CHANNEL];
  }
}
