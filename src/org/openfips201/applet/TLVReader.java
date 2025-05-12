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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Supports reading the modified BER-TLV format that is used by PIV for data objects. The format is
 * essentially BER-TLV, with the following exceptions: - The hierarchy is flat (constructed objects
 * are outside the scope of PIV to interpret itself) - The TAG identifier is non-compliant (no
 * class, no constructed flag, no length formatting)
 */
final class TLVReader {

  // The length of the entire TLV buffer for boundary checking
  private static final short CONTEXT_LENGTH = (short) 0;
  // The current position in the buffer
  private static final short CONTEXT_POSITION = (short) 1;
  // The offset given when the data was set, allowing for a reset
  private static final short CONTEXT_POSITION_RESET = (short) 2;
  private static final short LENGTH_CONTEXT = (short) 3;

  // TRANSIENT - Holds the current buffer
  private final Object[] dataPtr;

  // TRANSIENT - Holds the current context
  private final short[] context;

  // PERSISTENT - Holds the singleton instance
  private static TLVReader instance;

  private TLVReader() {
    dataPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
  }

  static TLVReader getInstance(byte[] buffer, short offset, short length) {
    if (instance == null) {
      allocate();
    }
    
    // Initialise the instance 
    instance.dataPtr[0] = buffer;
    instance.context[CONTEXT_POSITION] = offset;
    instance.context[CONTEXT_POSITION_RESET] = offset;
    instance.context[CONTEXT_LENGTH] = length;
    
    return instance;
  }

  static void allocate() {
    if (instance == null) {
      instance = new TLVReader();
    }
  }

  static void terminate() {
    instance = null;
    JCSystem.requestObjectDeletion();
  }

  /**
   * Returns the length of the data element for the tag found at offset
   *
   * @param data The data to search
   * @param offset The offset of the tag to read
   * @return The length of the data element
   */
  static short getLength(byte[] data, short offset) throws ISOException {
    // Move to the length field after skipping the tag.
    offset = skipTag(data, offset);

    // Is this a short-form length byte?
    if ((data[offset] & TLV.MASK_LONG_LENGTH) != TLV.MASK_LONG_LENGTH) {
      // short-form length
      return (short) (data[offset] & 0xFF);
    }

    // Is there more than 1 byte?
    if ((data[offset] & TLV.MASK_LENGTH) == 1) {
      // Values 0-255
      offset++;
      return (short) (data[offset] & 0xFF);
    } else if ((data[offset] & TLV.MASK_LENGTH) == 2) {
      // Values 0-65535
      // NOTE: Since we're assigning to a signed short, we don't
      // support anything greater than +32766.
      offset++;
      return Util.getShort(data, offset);
    } else {
      // We don't support multi-byte length definitions > 2
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) -1; // Dummy for compiler
    }
  }

  /**
   * Gets the offset to the data element of the tag found at the requested offset
   *
   * @param data The buffer containing the TLV object
   * @param offset The offset of the TLV element to inspect
   * @return The data element offset
   */
  static short getDataOffset(byte[] data, short offset) {
    // Skip the tag field
    offset = skipTag(data, offset);

    // Skip the length field to reach the data.
    return skipLength(data, offset);
  }

  // Helper: Skips the tag bytes and returns the offset to the length field.
  private static short skipTag(byte[] data, short offset) {
    if ((data[offset] & TLV.MASK_TAG_MULTI_BYTE) == TLV.MASK_TAG_MULTI_BYTE) {
      // Skip additional tag bytes
      do {
        offset++;
      } while ((data[offset] & TLV.MASK_HIGH_TAG_MOREDATA) == TLV.MASK_HIGH_TAG_MOREDATA);
    }
    return (short) (offset + 1); // Move past the tag field
  }

  // Helper: Skips the length field and returns the offset to the data.
  private static short skipLength(byte[] data, short offset) {
    if ((data[offset] & TLV.MASK_LONG_LENGTH) == TLV.MASK_LONG_LENGTH) {
      // Skip the extra length bytes
      offset += (byte) (data[offset] & TLV.MASK_LENGTH);
    }
    return (short) (offset + 1); // Move past the initial length byte
  }

  /***
   * Evaluates whether we have moved past the end of the buffer supplied at init()
   *
   * @return True if the current position exceeds the length of the supplied buffer
   */
  boolean isEOF() {
    return (context[CONTEXT_POSITION] >= (short) (context[CONTEXT_POSITION_RESET] + context[CONTEXT_LENGTH]));
  }

  /**
   * Moves to the next tag
   *
   * @return True if the move was successful, or False if the buffer was overrun
   */
  boolean moveNext() {
    // Skip to the next tag
    short dataLength = getLength();
    context[CONTEXT_POSITION] = getDataOffset();
    context[CONTEXT_POSITION] += dataLength;
    return ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET]) < context[CONTEXT_LENGTH]);
  }

  /**
   * Moves to the first tag inside the current tag
   *
   * @return True if the move was successful, or False if the buffer was overrun
   */
  boolean moveInto() {
    context[CONTEXT_POSITION] = getDataOffset();
    return ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET]) < context[CONTEXT_LENGTH]);
  }

  /**
   * Tests if the current tag matches the supplied one
   *
   * @param tag The tag to find
   * @return True if the current tag matches the supplied one
   */
  boolean match(byte tag) {
    if (isEOF()) {
      return false;
    } else {
      byte[] data = (byte[]) dataPtr[0];
      return (tag == data[context[CONTEXT_POSITION]]);
    }
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @return True if the first byte of the data matches the comparison
   */
  boolean matchData(byte value) {
    return matchData(value, (short) 0);
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @param offset The offset within the data to compare against
   * @return True if the first byte of the data matches the comparison
   */
  boolean matchData(byte value, short offset) { // NO_UCD
    byte[] data = (byte[]) dataPtr[0];
    offset += getDataOffset();
    return (value == data[offset]);
  }

  /**
   * Returns the tag identifier for the current tag
   *
   * @return The identifier for the current tag
   */
  byte getTag() {
    byte[] data = (byte[]) dataPtr[0];
    return data[context[CONTEXT_POSITION]];
  }

  /**
   * Gets the length of the current tag's data element
   *
   * @return The length of the current tag's data element
   */
  short getLength() {
    return getLength((byte[]) dataPtr[0], context[CONTEXT_POSITION]);
  }

  /**
   * Returns true of the current tag has a zero-length (empty) data element
   *
   * @return Whether the current tag has a zero length element
   */
  boolean isNull() {
    return (getLength() == (short) 0);
  }

  /**
   * Gets the current position within the TLV object
   *
   * @return The current position within the TLV object
   */
  short getOffset() {
    return context[CONTEXT_POSITION];
  }

  /**
   * Gets the offset in the current tag to it's data element
   *
   * @return The data offset in the current tag
   */
  short getDataOffset() {
    return getDataOffset((byte[]) dataPtr[0], context[CONTEXT_POSITION]);
  }

  /**
   * Returns the currently initialised buffer
   *
   * @return The currently initialised buffer
   */
  byte[] getData() {
    return (byte[]) dataPtr[0];
  }

  /**
   * Reads the current tag value as a short integer value
   *
   * @return The current tag value as a short integer
   */
  short toShort() throws ISOException {
    byte[] data = (byte[]) dataPtr[0];
    short length = getLength();
    short offset = getDataOffset();

    if ((short) 1 == length) {
      return (short) (data[offset] & 0xFF);
    } else if ((short) 2 == length) {
      return Util.getShort(data, offset);
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) -1; // Dummy
    }
  }

  /**
   * Reads the current tag value as a byte value
   *
   * @return The current tag value as a byte
   */
  byte toByte() throws ISOException {
    byte[] data = (byte[]) dataPtr[0];
    return data[getDataOffset()];
  }
}
