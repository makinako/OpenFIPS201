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
 * Supports writing the modified BER-TLV format that is used by PIV for data objects.
 * The format is essentially BER-TLV, with the following exceptions:
 * = The hierarchy is flat (constructed objects are outside the scope of PIV to interpret itself)
 * - The TAG identifier is non-compliant (no class, no constructed flag, no length formatting)
 */
public final class TLVWriter {

    //
    // CONSTANTS
    //
    public Object[] dataPtr;
    public short[] context;

    // The maximum number of data bytes for the payload, NOT including the main tag and length octets
    // NOTE:
    // - This governs how many bytes are reserved for the parent L value
    // - 1 byte = 0-127 bytes data length
    // - 2 bytes = 0-255 bytes data length
    // - 3 bytes = 0-32767 bytes data length (because of java signed type)
    private static final short CONTEXT_LENGTH_MAX		= (short)0;

    // The offset where the 2-byte length will be written at the end
    private static final short CONTEXT_LENGTH_PTR		= (short)1;

    // The current offset in the buffer
    private static final short CONTEXT_OFFSET			= (short)2;

    // The original offset in the buffer
    private static final short CONTEXT_OFFSET_RESET		= (short)3;

    private static final short LENGTH_CONTEXT			= (short)4;

    public static final short LENGTH_1BYTE_MAX			= (short)0x7F;
    public static final short LENGTH_2BYTE_MAX			= (short)0xFF;
    public static final short LENGTH_3BYTE_MAX			= (short)0x7FFF;

    public TLVWriter() {
        dataPtr = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Initialises the object with a data buffer, starting offset and content length
     * It is important that the supplied buffer has enough length for the content and
     * also the parent Tag and Length octets (2-6 bytes).
     * @param buffer The byte array to write to
     * @param offset The starting offset
     * @param contentLength the indicative length of the content that will be written
     * @param tag The parent tag value
     */
    public void init(byte[] buffer, short offset, short contentLength, short tag) {
        if (contentLength < (short)0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        dataPtr[0] = buffer;

        context[CONTEXT_OFFSET] = offset;
        context[CONTEXT_OFFSET_RESET] = offset;
        context[CONTEXT_LENGTH_MAX] = contentLength;

        // Set the parent TAG
        writeTag(tag);

        // Reserve the LENGTH value
        if (contentLength <= LENGTH_1BYTE_MAX) {
            // Store the offset where we will write the length at the end and increment
            context[CONTEXT_LENGTH_PTR] = context[CONTEXT_OFFSET]++;
        } else if (contentLength <= LENGTH_2BYTE_MAX) {
            // Reserve a 1-byte length
            buffer[context[CONTEXT_OFFSET]++] = (byte)0x81;

            // Store the offset where we will write the length at the end
            context[CONTEXT_LENGTH_PTR] = context[CONTEXT_OFFSET]++;

            // Move the position 1 forward
            context[CONTEXT_OFFSET]++;
        } else { // (contentLength <= LENGTH_3BYTE_MAX)
            // Reserve a 2-byte length
            buffer[context[CONTEXT_OFFSET]++] = (byte)0x82;

            // Store the offset where we will write the length at the end
            context[CONTEXT_LENGTH_PTR] = context[CONTEXT_OFFSET];

            // Move the position 2 forward
            context[CONTEXT_OFFSET] += (short)2;
        }
    }

    /**
     * Calculates the total object length for the parent constructed tag and clears all internal state
     * @return The length of the entire data object
     */
    public short finish() {

        // Write the length to the data object tag field
        if (dataPtr[0] == null) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        byte[] data = (byte[])dataPtr[0];

        // Write the now known the LENGTH value
        short l;
        if (context[CONTEXT_LENGTH_MAX] >= 0 && context[CONTEXT_LENGTH_MAX] <= LENGTH_1BYTE_MAX) {
            l = (short)(context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - 1);
            if (l > LENGTH_1BYTE_MAX) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            data[context[CONTEXT_LENGTH_PTR]] = (byte)(l & (short)0x007F);
        } else if (context[CONTEXT_LENGTH_MAX] >= 0 && context[CONTEXT_LENGTH_MAX] <= LENGTH_2BYTE_MAX) {
            l = (short)(context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - 1);
            if (l > LENGTH_2BYTE_MAX) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            data[context[CONTEXT_LENGTH_PTR]] = (byte)(l & (short)0x00FF);
        } else if (context[CONTEXT_LENGTH_MAX] >= 0 && context[CONTEXT_LENGTH_MAX] <= LENGTH_3BYTE_MAX) {
            l = (short)(context[CONTEXT_OFFSET] - context[CONTEXT_LENGTH_PTR] - 2);
            Util.setShort(data, context[CONTEXT_LENGTH_PTR], l);
        } else {
            // Invalid length supplied
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Update l to calculate the total length of bytes written
        l = (short)(context[CONTEXT_OFFSET] - context[CONTEXT_OFFSET_RESET]);

        // Clear any references to the data
        reset();

        // Done, return the total length
        return l;
    }

    /**
     * Clears the current state
     */
    public void reset() {
        dataPtr[0] = null;

        context[CONTEXT_OFFSET_RESET] = (short)0;
        context[CONTEXT_OFFSET] = (short)0;
        context[CONTEXT_LENGTH_PTR] = (short)0;
    }

    /**
     * Returns whether a TLV object is currently being written
     * @return Whether this instance is initialised
     */
    public boolean isInitialized() {
        return (dataPtr[0] != null);
    }

    /**
     * Adds an object with a byte value to the TLV object
     * @param tag The tag to write
     * @param value The value to write
     */
    public void write(short tag, byte value) {
        if (dataPtr[0] == null) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        byte[] data = (byte[])dataPtr[0];

        // TODO: Make sure we won't go over our length boundary

        // Set the TAG
        writeTag(tag);

        // Set the LENGTH
        data[context[CONTEXT_OFFSET]++] = (byte)1;

        // Set the VALUE
        data[context[CONTEXT_OFFSET]++] = value;
    }

    /**
     * Adds an object with a short value to the TLV object
     * @param tag The tag to write
     * @param value The value to write
     */
    public void write(short tag, short value) {
        if (dataPtr[0] == null) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        byte[] data = (byte[])dataPtr[0];

        // TODO: Make sure we won't go over our length boundary

        // Set the TAG
        writeTag(tag);

        // Set the LENGTH
        data[context[CONTEXT_OFFSET]++] = (byte)2;

        // Set the VALUE
        Util.setShort(data, context[CONTEXT_OFFSET], value);

        context[CONTEXT_OFFSET] += (short)2;
    }

    /**
     * Adds an object with a byte array value to the TLV object
     * @param tag The tag to write
     * @param buffer The byte array to read from
     * @param offset The starting offset for the input array
     * @param length The number of bytes to read from the input array
     */
    public void write(short tag, byte[] buffer, short offset, short length) {

        if (dataPtr[0] == null) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        byte[] data = (byte[])dataPtr[0];

        // TODO: Make sure we won't go over our length boundary

        // Set the TAG
        writeTag(tag);

        // Set the LENGTH
        writeLength(length);

        // Set the VALUE
        Util.arrayCopy(buffer, offset, data, context[CONTEXT_OFFSET], length);

        // Increment the position / length
        context[CONTEXT_OFFSET] += length;
    }

    /**
     * Adds an object with no value to the TLV object
     * @param tag The tag to write
     */
    public void writeNull(short tag) {

        if (dataPtr[0] == null) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        byte[] data = (byte[])dataPtr[0];

        // TODO: Make sure we won't go over our length boundary

        // Set the TAG
        writeTag(tag);

        // Set the LENGTH
        data[context[CONTEXT_OFFSET]++] = (byte)0;

        // There is no VALUE element
    }

    /**
     * Writes the TAG portion of an object only
     * @param tag The tag to write
     * @return The length of the tag bytes written
     */
    public short writeTag(byte tag) {
        return writeTag((short)(tag & 0xFF));
    }

    /**
     * Writes the TAG portion of an object only
     * @param tag The tag to write
     * @return The length of the tag bytes written
     */
    public short writeTag(short tag) {

        if (tag >= 0 && tag <= 255) {
            // Single-byte tag
            ((byte[])dataPtr[0])[context[CONTEXT_OFFSET]] = (byte)tag;
            context[CONTEXT_OFFSET]++;
            return (short)1; // Length of the tag
        } else {
            // Double-byte tag
            Util.setShort((byte[])dataPtr[0], context[CONTEXT_OFFSET], tag);
            context[CONTEXT_OFFSET] += (short)2;
            return (short)2; // Length of the tag
        }
    }

    /**
     * Writes the LENGTH portion of an object only
     * @param length The length value to write
     * @return The length of the Length bytes written
     */
    public short writeLength(short length) {

        byte[] data = (byte[])dataPtr[0];

        // Set the LENGTH
        if (length >= 0 && length <= 127) {
            // Single-byte length
            data[context[CONTEXT_OFFSET]++] = (byte)length;
            return (short)1;
        } else if (length > 127 && length <= 255) {
            // Double-byte length
            data[context[CONTEXT_OFFSET]++] = (byte)0x81;
            data[context[CONTEXT_OFFSET]++] = (byte)length;
            return (short)2;
        } else {
            // Triple-byte length
            data[context[CONTEXT_OFFSET]++] = (byte)0x82;
            Util.setShort(data, context[CONTEXT_OFFSET], length);
            context[CONTEXT_OFFSET] += (short)2;
            return (short)3;
        }
    }

    /**
     * Updates the current position within the buffer to write to
     * @param offset The new value to set the offset to
     */
    public void setOffset(short offset) {
        context[CONTEXT_OFFSET] = offset;
    }

    /**
     * Returns the current position within the buffer being written to
     * @return The offset within the current buffer
     */
    public short getOffset() {
        return context[CONTEXT_OFFSET];
    }
}