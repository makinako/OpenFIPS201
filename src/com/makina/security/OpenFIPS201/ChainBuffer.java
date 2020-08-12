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

package com.makina.security.OpenFIPS201;

import javacard.framework.*;

/**
 * ChainBuffer supports reading and writing of buffers larger than a single APDU frame. It takes
 * away the responsibility of dealing with the actual read and write operations, state management
 * and transaction management from the APDU processing functions. Instead each function that needs
 * to support chained reads or writes simply calls this method with a buffer to act on and
 * ChainBuffer will do the rest.
 */
public final class ChainBuffer {

  // The chain context is inactive and buffer does not point to anything
  public static final short STATE_NONE = (short) 0x00;

  // The chain context is reading (supporting multiple GET RESPONSE commands)
  public static final short STATE_OUTGOING = (short) 0x01;

  // The chain context is writing (supporting chained commands of whatever INS started it)
  public static final short STATE_INCOMING_OBJECT = (short) 0x02;

  // The chain context is writing (supporting chained commands of whatever INS started it)
  public static final short STATE_INCOMING_APDU = (short) 0x03;

  // The chain state
  private static final short CONTEXT_STATE = (short) 0;

  // The current offset in the data buffer
  private static final short CONTEXT_OFFSET = (short) 1;

  // The initial offset in the data buffer that was supplied by the caller
  private static final short CONTEXT_INITIAL = (short) 2;

  // The total length of the data buffer
  private static final short CONTEXT_LENGTH = (short) 3;

  // The number of remaining bytes to write or read in the buffer
  private static final short CONTEXT_REMAINING = (short) 4;

  // Indicates whether the buffer should be wiped on completion of the chain
  private static final short CONTEXT_CLEAR_ON_COMPLETE = (short) 5;

  // Indicates whether the chain is operating inside a transaction
  private static final short CONTEXT_TRANSACTION = (short) 6;

  // The APDU header used for tracking incoming data
  // NOTE: It's cheaper to use 4 shorts in this array than to allocate a separate 4 bytes, as the
  // minimum allocation size is 32 bytes anyway
  private static final short CONTEXT_APDU_CLASS = (short) 8;
  private static final short CONTEXT_APDU_P1P2 = (short) 9;

  // Total length of the context transient object
  private static final short LENGTH_CONTEXT = (short) 10;

  // APDU constants
  private static final byte CLA_CHAINING = (byte) 0x10;
  private static final byte INS_GET_RESPONSE = (byte) 0xC0;

  // A pointer to our read/write data buffer
  private final Object[] dataPtr;

  // Holds transient context information about the current chain
  private final short[] context;

  public ChainBuffer() {

    dataPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
  }

  /** Resets the ChainBuffer, aborting any outstanding transaction */
  private void resetAbort() {

    // Have we been asked to conduct this in a transaction?
    if ((short) 0 != context[CONTEXT_TRANSACTION]) {
      JCSystem.abortTransaction();
    }

    // Perform a normal reset
    reset();
  }

  /** Resets the ChainBuffer, committing any outstanding transaction */
  private void resetCommit() {

    // Have we been asked to conduct this in a transaction?
    if ((short) 0 != context[CONTEXT_TRANSACTION]) {
      JCSystem.commitTransaction();
    }

    // Perform a normal reset
    reset();
  }

  /** Resets the ChainBuffer and clears any internal buffer and state tracking values */
  public void reset() {

    // Have we been asked to clear the buffer?
    if (dataPtr[0] != null && context[CONTEXT_CLEAR_ON_COMPLETE] != (short) 0) {
      Util.arrayFillNonAtomic(
          (byte[]) dataPtr[0], context[CONTEXT_INITIAL], context[CONTEXT_LENGTH], (byte) 0x00);
    }

    // Burn them... Burn them all
    dataPtr[0] = null;
    context[CONTEXT_STATE] = STATE_NONE;

    context[CONTEXT_OFFSET] = (short) 0;
    context[CONTEXT_INITIAL] = (short) 0;
    context[CONTEXT_REMAINING] = (short) 0;
    context[CONTEXT_LENGTH] = (short) 0;
    context[CONTEXT_CLEAR_ON_COMPLETE] = (short) 0;
    context[CONTEXT_APDU_CLASS] = (short) 0;
    context[CONTEXT_APDU_P1P2] = (short) 0;
    context[CONTEXT_TRANSACTION] = (short) 0;
  }

  /**
   * Configures the ChainBuffer class to process a stream of outgoing data which will be retrieved
   * by subsequent GET RESPONSE commands
   *
   * @param buffer the buffer to read data from
   * @param offset The starting offset of the data to read from
   * @param length The total number of bytes to read
   * @param clearOnCompletion If true, the buffer will be wiped when the chain operation ends
   */
  public void setOutgoing(byte[] buffer, short offset, short length, boolean clearOnCompletion) {

    reset();

    dataPtr[0] = buffer;

    context[CONTEXT_STATE] = STATE_OUTGOING;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_INITIAL] = offset;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;
    context[CONTEXT_CLEAR_ON_COMPLETE] = clearOnCompletion ? (short) 1 : (short) 0;
  }

  /**
   * Configures the ChainBuffer class to process a stream of incoming data directly to an object
   *
   * @param destination The buffer to write data to
   * @param offset The starting offset of the data to write to
   * @param length The length to expect to be written
   * @param atomic If true, this operation will be conducted inside a transaction
   */
  public void setIncomingObject(byte[] destination, short offset, short length, boolean atomic) {

    reset();

    dataPtr[0] = destination;

    context[CONTEXT_STATE] = STATE_INCOMING_OBJECT;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;

    if (atomic) {
      JCSystem.beginTransaction();
      context[CONTEXT_TRANSACTION] = (short) 1;
    }
  }

  /**
   * Used to pre-validate an incoming APDU, to support cancelling mid-command. Note that this
   * function does not process the APDU at all, it simply checks whether the command has been
   * changed before completion. If so, it cancels and optionally allows the APDU the continue being
   * processed by the applet.
   *
   * @param apdu The incoming APDU buffer
   * @param inOffset The starting offset of initial APDU
   * @param inLength The length of the initial APDU
   */
  public void checkIncomingAPDU(byte[] apdu, short inOffset, short inLength) {

    final short CLA_MASK = ~(short) 0x1000;

    // Check if we have anything to do
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU) return;

    // If the command has changed, cancel the previous incoming APDU and continue.
    if ((context[CONTEXT_APDU_CLASS] & CLA_MASK) != Util.getShort(apdu, ISO7816.OFFSET_CLA)
        || context[CONTEXT_APDU_P1P2] != Util.getShort(apdu, ISO7816.OFFSET_P1)) {
      // Cancel the previous incoming APDU
      reset();

      if (Config.FEATURE_STRICT_APDU_CHAINING) {
        // For implementations that wish to force the completion of chained commands,
        // this optionally throws an exception.
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }
    }

    // If we have passed, the applet will continue and direct this APDU to the appropriate
    // handler, which will then call processIncomingAPDU() to complete this.
  }

  /**
   * Configures the ChainBuffer class to process a large incoming APDU
   *
   * @param apdu The first incoming APDU buffer
   * @param inOffset The starting offset of initial APDU
   * @param inLength The length of the initial APDU
   * @param outBuffer The destination buffer for the large APDU CDATA content
   * @param outOffset The offset to start writing in the destination buffer
   * @return The number of bytes in the command data if complete, otherwise zero to indicate there
   *     is more to come NOTE: The destination will contain only the command data of the APDU, not
   *     the header.
   */
  public short processIncomingAPDU(
      byte[] apdu, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

    //
    // STATE VALIDATION
    //

    // Make sure that we are not in the middle of some other outstanding transaction
    if (context[CONTEXT_STATE] != STATE_NONE && context[CONTEXT_STATE] != STATE_INCOMING_APDU) {
      // We have been called in the middle of another operation! call resetAbort in case there is
      // some outstanding transaction
      resetAbort();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // CASE 1 - A single-frame APDU (CLA_CHAINING == FALSE and STATE == STATE_NONE)
    //
    if ((apdu[ISO7816.OFFSET_CLA] & CLA_CHAINING) == 0 && context[CONTEXT_STATE] == STATE_NONE) {

      // Just copy the buffer to the destination and we are done
      try {
        Util.arrayCopyNonAtomic(apdu, inOffset, outBuffer, outOffset, inLength);
      } catch (Exception ex) {
        // Buffer overrun
        reset();
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }

      // We're done! No state needs to change, just return the value of the LC byte (length of
      // command data)
      return inLength;
    }

    //
    // CASE 2 - The start of an incoming APDU chain (CLA_CHAINING == TRUE and STATE == STATE_NONE)
    //
    else if ((apdu[ISO7816.OFFSET_CLA] & CLA_CHAINING) != 0
        && context[CONTEXT_STATE] == STATE_NONE) {

      // Set up the internal state
      context[CONTEXT_STATE] = STATE_INCOMING_APDU;
      context[CONTEXT_INITIAL] = inOffset;
      context[CONTEXT_APDU_CLASS] = Util.getShort(apdu, ISO7816.OFFSET_CLA);
      context[CONTEXT_APDU_P1P2] = Util.getShort(apdu, ISO7816.OFFSET_P1);

      // Write the first section of data
      try {
        Util.arrayCopyNonAtomic(apdu, inOffset, outBuffer, outOffset, inLength);
      } catch (Exception ex) {
        // Buffer overrun
        reset();
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }

      context[CONTEXT_LENGTH] = inLength;

      // Done, return 0 so the caller knows we're not finished!
      return (short) 0;
    }

    //
    // CASE 3 - The middle of an incoming APDU chain (CLA_CHAINING == TRUE and STATE ==
    // STATE_INCOMING_APDU)
    //
    else if ((apdu[ISO7816.OFFSET_CLA] & CLA_CHAINING) != 0
        && context[CONTEXT_STATE] == STATE_INCOMING_APDU) {

      // Validate that we are chaining for the correct command
      if (context[CONTEXT_APDU_CLASS] != Util.getShort(apdu, ISO7816.OFFSET_CLA)
          || context[CONTEXT_APDU_P1P2] != Util.getShort(apdu, ISO7816.OFFSET_P1)) {
        reset();

        // NOTE regarding Config.FEATURE_STRICT_APDU_CHAINING:
        // If we have gotten here, then checkIncomingAPDU was not called. Since we are
        // already past the point of allowing the applet to switch to other commands,
        // so we always fail. Use checkIncomingAPDU() and this will never be reached.
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }

      // Calculate the outOffset by adding the amount of data we have already written
      outOffset += context[CONTEXT_LENGTH];

      // Write the next section of data
      try {
        Util.arrayCopyNonAtomic(apdu, inOffset, outBuffer, outOffset, inLength);
      } catch (Exception ex) {
        // Buffer overrun
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Update the internal state
      context[CONTEXT_LENGTH] += inLength;

      // Done, return 0 so the caller knows we're not finished!
      return (short) 0;
    }

    //
    // CASE 4 - The end of an incoming APDU chain (CLA_CHAINING == FALSE and STATE ==
    // STATE_INCOMING_APDU)
    //
    else if ((apdu[ISO7816.OFFSET_CLA] & CLA_CHAINING) == 0
        && context[CONTEXT_STATE] == STATE_INCOMING_APDU) {

      // Validate that we are chaining for the correct command
      // NOTE: We have to mask off the chaining bit before comparing
      final short CLA_MASK = ~(short) 0x1000;
      if ((context[CONTEXT_APDU_CLASS] & CLA_MASK) != Util.getShort(apdu, ISO7816.OFFSET_CLA)
          || context[CONTEXT_APDU_P1P2] != Util.getShort(apdu, ISO7816.OFFSET_P1)) {
        reset();

        // NOTE regarding Config.FEATURE_STRICT_APDU_CHAINING:
        // If we have gotten here, then checkIncomingAPDU was not called. Since we are
        // already past the point of allowing the applet to switch to other commands,
        // so we always fail. Use checkIncomingAPDU() and this will never be reached.
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }

      // Calculate the outOffset by adding the amount of data we have already written
      outOffset += context[CONTEXT_LENGTH];

      // Write the final section of data
      try {
        Util.arrayCopyNonAtomic(apdu, inOffset, outBuffer, outOffset, inLength);
      } catch (Exception ex) {
        // Buffer overrun
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Calculate our final length
      inLength += context[CONTEXT_LENGTH];

      // Reset our internal state
      reset();

      // Done, return the total length!
      return inLength;
    }

    //
    // Unexpected state
    //

    // Should never reach this state, throw back SW_UNKNOWN to flag we have a bug
    reset();
    ISOException.throwIt(ISO7816.SW_UNKNOWN);
    return (short) 0; // Keep the compiler happy
  }

  /**
   * Starts or continues processing of an incoming data stream, which will be written directly to a
   * buffer
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset to read from
   * @param length The length of the data to read
   */
  public void processIncomingObject(byte[] buffer, short offset, short length) {

    // Check if we have anything to do
    if (context[CONTEXT_STATE] != STATE_INCOMING_OBJECT) return;

    // This method presumes that setIncomingAndReceive() was previously called if required
    final short CLA_MASK = ~(short) 0x1000;

    // If we have not written anything, this must be the first command so set the APDU header
    if (context[CONTEXT_LENGTH] == context[CONTEXT_REMAINING]) {
      context[CONTEXT_APDU_CLASS] = (short) (Util.getShort(buffer, ISO7816.OFFSET_CLA) & CLA_MASK);
      context[CONTEXT_APDU_P1P2] = Util.getShort(buffer, ISO7816.OFFSET_P1);
    }

    // Validate that we are chaining for the correct command
    else if (context[CONTEXT_APDU_CLASS]
            != (short) ((Util.getShort(buffer, ISO7816.OFFSET_CLA) & CLA_MASK))
        || context[CONTEXT_APDU_P1P2] != Util.getShort(buffer, ISO7816.OFFSET_P1)) {

      // Abort the data object write
      resetAbort();

      if (Config.FEATURE_STRICT_APDU_CHAINING) {
        // For implementations that wish to force the completion of chained commands,
        // this optionally throws an exception.
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      } else {
        // Ignore this and let the applet handle as a new APDU
        return;
      }
    }

    // Check if we are chaining or not (we don't use the in-built APDU.isCommandChainingCLA() call
    // because it doesn't always work!
    if ((buffer[ISO7816.OFFSET_CLA] & CLA_CHAINING) != 0) {

      //
      // CASE 0: If the chaining bit is SET, we are writing the first or an intermediary frame
      // 		   and we must not write up to or over the total expected length
      //

      // No data to write? Nothing to do.. What a waste of everyone's time
      if (length == 0) return;

      if (length >= context[CONTEXT_REMAINING]) {
        resetAbort();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Write to the data buffer and update our context
      if ((short) 0 != context[CONTEXT_TRANSACTION]) {
        Util.arrayCopy(buffer, offset, (byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);
      } else {
        Util.arrayCopyNonAtomic(
            buffer, offset, (byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);
      }
      context[CONTEXT_OFFSET] += length;
      context[CONTEXT_REMAINING] -= length;
    } else {

      //
      // CASE 1: If the chaining bit is NOT SET, we must be writing either the last or the only
      // frame
      //		   and we must write exactly up to the length of the data buffer
      //

      if (length == 0) {
        resetAbort();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Must be exactly the # of bytes remaining
      if (length != context[CONTEXT_REMAINING]) {
        resetAbort();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Write to the data buffer and update our context
      Util.arrayCopy(buffer, offset, (byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);

      // Clear our context as the chain is now complete
      resetCommit();
    }
    ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }

  /**
   * Starts or continues processing for an outgoing buffer being transmitted to the host
   *
   * @param apdu The current APDU buffer to transmit with
   */
  public void processOutgoing(APDU apdu) {

    // Check if we have anything to do
    if (context[CONTEXT_STATE] != STATE_OUTGOING) return;

    byte[] apduBuffer = apdu.getBuffer();

    // CASE 0 - If the remaining data is EQUAL TO the total data, ignore the INS
    // CASE 1 - If the remaining data is LESS THAN the total data, look for a GET RESPONSE command
    // (clear if it isn't)
    if (apduBuffer[ISO7816.OFFSET_INS] != INS_GET_RESPONSE
        && context[CONTEXT_REMAINING] != context[CONTEXT_LENGTH]) {

      // Clear the apdu buffer
      reset();

      if (Config.FEATURE_STRICT_APDU_CHAINING) {
        // For implementations that wish to force the completion of chained commands,
        // this optionally throws an exception.
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      } else {
        // Ignore this and let the applet handle this as a new command
        return;
      }
    }

    //
    // Transmit the next frame up to a maximum of 'LE' bytes
    //

    short le = apdu.setOutgoing();

    //
    // !! HACK !!
    // Most applets completely ignore this value and so interface developers have gotten lazy about
    // whether or not they include an LE byte when they expect response data.
    // This treats the absence of an LE byte (case 3) as if it were a case 4 byte with LE == '00',
    // which maps to 256 bytes.
    //
    if (le == 0) le = 256;

    short length = (context[CONTEXT_REMAINING] > le) ? le : context[CONTEXT_REMAINING];

    apdu.setOutgoingLength(length);
    apdu.sendBytesLong((byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);

    context[CONTEXT_REMAINING] -= length;
    context[CONTEXT_OFFSET] += length;

    // If we have nothing left to send, clear our context and return 9000
    if (context[CONTEXT_REMAINING] == 0) {
      reset();
      ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    // Otherwise, notify the caller we have xx remaining bytes (up to 255)
    else {
      short sw2 =
          (context[CONTEXT_REMAINING] > (short) 0xFF) ? (short) 0xFF : context[CONTEXT_REMAINING];
      ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | sw2));
    }
  }
}
