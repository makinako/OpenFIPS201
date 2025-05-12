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
 * Supports writing the modified BER-TLV format that is used by PIV for data objects. The format is
 * essentially BER-TLV, with the following exceptions: = The hierarchy is flat (constructed objects
 * are outside the scope of PIV to interpret itself) - The TAG identifier is non-compliant (no
 * class, no constructed flag, no length formatting)
 */
final class TLVWriter {

  // The maximum number of data bytes for the payload, NOT including the main tag and length octets
  // NOTE:
  // - This governs how many bytes are reserved for the parent L value
  // - 1 byte = 0-127 bytes data length
  // - 2 bytes = 0-255 bytes data length
  // - 3 bytes = 0-32767 bytes data length (because of java signed type)
  private static final short CONTEXT_LENGTH_MAX = (short) 0;
  // The offset where the the final constructed tag length will be written, if at all 
  private static final short CONTEXT_LENGTH_PTR = (short) 1;
  // The current offset in the buffer
  private static final short CONTEXT_OFFSET = (short) 2;
  // The original offset in the buffer
  private static final short CONTEXT_OFFSET_RESET = (short) 3;

  private static final short LENGTH_CONTEXT = (short) 4;

  //
  // CONSTANTS
  //
  private final Object[] dataPtr;
  private final short[] context;

  private static TLVWriter instance;

  private TLVWriter() {
    dataPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
  }

  static TLVWriter getInstance() {
    if (instance == null) {
      allocate();
    }
    instance.reset();
    return instance;
  }

  static void allocate() {
    if (instance == null) {
      instance = new TLVWriter();
    }
  }

  static void terminate() {
    instance = null;
    JCSystem.requestObjectDeletion();
  }

  /**
   * Initialises the object with a data buffer and starting offset, but no parent tag
   *
   * @param buffer The byte array to write to
   * @param offset The starting offset
   * @param maxLength the indicative maximum length of the expected content.
   * @param tag The parent tag value
   */
  void init(byte[] buffer, short offset) throws ISOException { // NO_UCD
    if (buffer == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return; // Make static analyser happy
    }

    dataPtr[0] = buffer;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_OFFSET_RESET] = offset;

    // No parent TLV is being written; mark this by setting CONTEXT_LENGTH_BYTES to 0.
    context[CONTEXT_LENGTH_PTR] = 0;

    // The maxLength field is irrelevant in flat mode.
    context[CONTEXT_LENGTH_MAX] = 0;
  }

  /**
   * Initialises the object with a data buffer, starting offset and content length It is important
   * that the supplied buffer has enough length for the content and also the parent Tag and Length
   * octets (2-6 bytes).
   *
   * @param buffer The byte array to write to
   * @param offset The starting offset
   * @param maxLength the indicative maximum length of the expected content.
   * @param tag The parent tag value
   */
  void init(byte[] buffer, short offset, short maxLength, byte tag) throws ISOException {
    init(buffer, offset);

    // Set the parent TAG
    writeTagByte(tag);

    // Reserve the LENGTH value
    reserveLength(maxLength);
  }

  /**
   * Initialises the object with a data buffer, starting offset and content length It is important
   * that the supplied buffer has enough length for the content and also the parent Tag and Length
   * octets (2-6 bytes).
   *
   * @param buffer The byte array to write to
   * @param offset The starting offset
   * @param maxLength the indicative maximum length of the expected content.
   * @param tag The parent tag value
   */
  void init(byte[] buffer, short offset, short maxLength, short tag) throws ISOException {
    init(buffer, offset);

    // Set the parent TAG
    writeTagShort(tag);

    // Reserve the LENGTH value
    reserveLength(maxLength);
  }

  private void reserveLength(short maxLength) {
    // Reserve the LENGTH value
    short reserved;
    if (maxLength <= TLV.LENGTH_1BYTE_MAX) {
      reserved = 1;
      context[CONTEXT_LENGTH_MAX] = TLV.LENGTH_1BYTE_MAX;
    } else if (maxLength <= TLV.LENGTH_2BYTE_MAX) {
      reserved = 2;
      context[CONTEXT_LENGTH_MAX] = TLV.LENGTH_2BYTE_MAX;
    } else { // (maxLength <= LENGTH_3BYTE_MAX)
      reserved = 3;
      context[CONTEXT_LENGTH_MAX] = TLV.LENGTH_3BYTE_MAX;
    }

    // Mark the original offset for the length and move to the new position
    context[CONTEXT_LENGTH_PTR] = context[CONTEXT_OFFSET];
    context[CONTEXT_OFFSET] += reserved;
  }

  byte[] getBuffer() {
    return (byte[])dataPtr[0];
  }
  
  /**
   * Calculates the total object length for the parent constructed tag and clears all internal state
   *
   * @return The length of the entire data object
   */
  short finish() throws ISOException {
    // Write the length to the data object tag field
    if (dataPtr[0] == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Write the now known the LENGTH value
    if (context[CONTEXT_LENGTH_PTR] != 0) {
      byte[] data = (byte[]) dataPtr[0];

      short finalLength;
      if (context[CONTEXT_LENGTH_MAX] <= TLV.LENGTH_1BYTE_MAX) {
        finalLength = (short) (context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - TLV.LENGTH_1BYTE);
      } else if (context[CONTEXT_LENGTH_MAX] <= TLV.LENGTH_2BYTE_MAX) {
        finalLength = (short) (context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - TLV.LENGTH_2BYTE);
      } else { // context[CONTEXT_LENGTH_MAX] <= TLV.LENGTH_3BYTE_MAX)
        finalLength = (short) (context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - TLV.LENGTH_3BYTE);
      }

      // Check if we have exceeded our maximum
      if (finalLength > context[CONTEXT_LENGTH_MAX]) {
        reset();
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      // Write the length
      writeLength(data, context[CONTEXT_LENGTH_PTR], finalLength);
    }

    // Update length to calculate the total length of bytes written
    short totalLength = (short) (context[CONTEXT_OFFSET] - context[CONTEXT_OFFSET_RESET]);

    // Reset all internal state
    reset();

    // Done, return the total length written
    return totalLength;
  }

  /** Clears the current state */
  private void reset() {
    dataPtr[0] = null;

    context[CONTEXT_OFFSET_RESET] = (short) 0;
    context[CONTEXT_OFFSET] = (short) 0;
    context[CONTEXT_LENGTH_PTR] = (short) 0;
    context[CONTEXT_LENGTH_MAX] = (short) 0;
  }

  /**
   * Progresses the write pointer forward when you have written to the buffer in some other way.
   *
   * @param length The number of elements to progress forward.
   */
  void move(short length) {
    context[CONTEXT_OFFSET] += length;
  }

  /**
   * Adds an object with a byte value to the TLV object
   *
   * @param tag The tag to write
   * @param value The value to write
   */
  void write(byte tag, byte value) throws ISOException {
    if (dataPtr[0] == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    byte[] data = (byte[]) dataPtr[0];

    // Set the TAG
    writeTagByte(tag);

    // Set the LENGTH
    data[context[CONTEXT_OFFSET]++] = (byte) 1;

    // Set the VALUE
    data[context[CONTEXT_OFFSET]++] = value;
  }

  /**
   * Adds an object with a byte value to the TLV object
   *
   * @param tag The tag to write
   * @param value The value to write
   */
  void write(byte tag, int value) throws ISOException {
    if (dataPtr[0] == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    byte[] data = (byte[]) dataPtr[0];

    // Set the TAG
    writeTagByte(tag);

    // Compute the necessary length to hold the integer value
    short length = 0;
    if ((value & 0xFF0000) != 0) {
        length = 3;  // The value needs three bytes
    } else if ((value & 0xFF00) != 0) {
        length = 2;  // The value needs two bytes
    } else if ((value & 0xFF) != 0) {
        length = 1;  // The value needs one byte
    }

    // Write the length
    data[context[CONTEXT_OFFSET]++] = (byte) length;

    // Write the value according to the calculated length
    for (short i = 0; i < length; i++) {
        data[(short)(context[CONTEXT_OFFSET] + i)] = (byte) ((value >> (8 * (length - i - 1))) & 0xFF);
    }    
    context[CONTEXT_OFFSET] += length;
  }

  /**
   * Adds an object with a byte array value to the TLV object
   *
   * @param tag The tag to write
   * @param buffer The byte array to read from
   * @param offset The starting offset for the input array
   * @param length The number of bytes to read from the input array
   */
  void write(byte tag, byte[] buffer, short offset, short length) throws ISOException {

    if (dataPtr[0] == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    byte[] data = (byte[]) dataPtr[0];

    // Set the TAG
    writeTagByte(tag);

    // Set the LENGTH
    writeLength(length);

    // Set the VALUE
    Util.arrayCopy(buffer, offset, data, context[CONTEXT_OFFSET], length);

    // Increment the position / length
    context[CONTEXT_OFFSET] += length;
  }

  /**
   * Adds an object with a byte array value to the TLV object
   *
   * @param tag The tag to write
   * @param buffer The byte array to read from
   * @param offset The starting offset for the input array
   * @param length The number of bytes to read from the input array
   */
  void write(short tag, byte[] buffer, short offset, short length) throws ISOException {

    if (dataPtr[0] == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    byte[] data = (byte[]) dataPtr[0];

    // Set the TAG
    writeTagShort(tag);

    // Set the LENGTH
    writeLength(length);

    // Set the VALUE
    Util.arrayCopy(buffer, offset, data, context[CONTEXT_OFFSET], length);

    // Increment the position / length
    context[CONTEXT_OFFSET] += length;
  }

  /**
   * Writes the TAG portion of an object only
   *
   * @param tag The tag to write
   * @return The length of the tag bytes written
   */
  short writeTagByte(byte tag) {
    ((byte[]) dataPtr[0])[context[CONTEXT_OFFSET]] = tag;
    context[CONTEXT_OFFSET]++;
    return (short) 1; // Length of the tag
  }

  /**
   * Writes the TAG portion of an object only
   *
   * @param tag The tag to write
   * @return The length of the tag bytes written
   */
  short writeTagShort(short tag) {
    if (tag >= 0 && tag <= 255) {
      // Single-byte tag
      ((byte[]) dataPtr[0])[context[CONTEXT_OFFSET]] = (byte) tag;
      context[CONTEXT_OFFSET]++;
      return (short) 1; // Length of the tag
    } else {
      // Double-byte tag
      context[CONTEXT_OFFSET] = Util.setShort((byte[]) dataPtr[0], context[CONTEXT_OFFSET], tag);
      return (short) 2; // Length of the tag
    }
  }

  /**
   * Writes the LENGTH portion of an object only
   *
   * @param length The length value to write
   * @return The length of the Length bytes written
   */
  short writeLength(short length) {
    context[CONTEXT_OFFSET] = writeLength((byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);
    return context[CONTEXT_OFFSET];
  }

  /**
   * Writes the LENGTH portion of an object only
   *
   * @param length The length value to write
   * @return The length of the Length bytes written
   */
  static short writeLength(byte[] buffer, short offset, short length) {

    // Set the LENGTH
    if (length >= 0 && length <= 127) {
      // Single-byte length
      buffer[offset++] = (byte) length;
    } else if (length > 127 && length <= 255) {
      // Double-byte length
      buffer[offset++] = (byte) 0x81;
      buffer[offset++] = (byte) length;
    } else {
      // Triple-byte length
      buffer[offset++] = (byte) 0x82;
      offset = Util.setShort(buffer, offset, length);
    }

    return offset;
  }

  /**
   * Returns the current position within the buffer being written to
   *
   * @return The offset within the current buffer
   */
  short getOffset() {
    return context[CONTEXT_OFFSET];
  }

  /**
   * Updates the current position within the buffer to write to
   *
   * @param offset The new value to set the offset to
   */
  void setOffset(short offset) {
    context[CONTEXT_OFFSET] = offset;
  }
}
