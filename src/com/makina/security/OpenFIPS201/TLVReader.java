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
 * Supports reading the modified BER-TLV format that is used by PIV for data objects.
 * The format is essentially BER-TLV, with the following exceptions:
 * - The hierarchy is flat (constructed objects are outside the scope of PIV to interpret itself)
 * - The TAG identifier is non-compliant (no class, no constructed flag, no length formatting)
 */
public final class TLVReader {

    // Tag Class
    public static final byte CLASS_UNIVERSAL 		= (byte)0x00;
    public static final byte CLASS_APPLICATION 		= (byte)0x40;
    public static final byte CLASS_CONTEXT 			= (byte)0x80;
    public static final byte CLASS_PRIVATE 			= (byte)0xC0;

    // Masks
    public static final byte MASK_CONSTRUCTED 			= (byte) 0x20;
    public static final byte MASK_LOW_TAG_NUMBER 		= (byte) 0x1F;
    public static final byte MASK_HIGH_TAG_NUMBER 		= (byte) 0x7F;
    public static final byte MASK_HIGH_TAG_MOREDATA 	= (byte) 0x80;
    public static final byte MASK_LONG_LENGTH 			= (byte) 0x80;
    public static final byte MASK_LENGTH 				= (byte) 0x7F;

    // Universal tags
    public static final byte ASN1_BOOLEAN 		= (byte)0x01;
    public static final byte ASN1_INTEGER 		= (byte)0x02;
    public static final byte ASN1_BIT_STRING 	= (byte)0x03;
    public static final byte ASN1_OCTET_STRING 	= (byte)0x04;
    public static final byte ASN1_NULL 			= (byte)0x05;
    public static final byte ASN1_OBJECT 		= (byte)0x06;
    public static final byte ASN1_ENUMERATED	= (byte)0x0A;
    public static final byte ASN1_SEQUENCE 		= (byte)0x10; //  "Sequence" and "Sequence of"
    public static final byte ASN1_SET 			= (byte)0x11; //  "Set" and "Set of"
    public static final byte ASN1_PRINT_STRING 	= (byte)0x13;
    public static final byte ASN1_T61_STRING 	= (byte)0x14;
    public static final byte ASN1_IA5_STRING 	= (byte)0x16;
    public static final byte ASN1_UTC_TIME 		= (byte)0x17;

    //
    // CONSTANTS
    //
    public Object[] dataPtr;
    public short[] context;

    // The length of the entire TLV buffer for boundary checking
    private static final short CONTEXT_LENGTH			= (short)0;

    // The current position in the buffer
    private static final short CONTEXT_POSITION			= (short)1;

    // The offset given when the data was set, allowing for a reset
    private static final short CONTEXT_POSITION_RESET	= (short)2;

    //
    // TODO: Cache Tag, Length and ValueOffset values when find() completes, so that
    // other subsequent calls can easily refer to them and there isn't so much redundant code
    //
    //private static final short CONTEXT_T					= (short)4;
    //private static final short CONTEXT_L					= (short)5;
    //private static final short CONTEXT_V					= (short)6;

    private static final short LENGTH_CONTEXT			= (short)4;

    public TLVReader() {
        dataPtr = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
    }


    /**
     * Initialises the TLVReader object with a data buffer, starting offset and length
     * @param buffer The buffer to read the object from
     * @param offset The starting offset for the object
     * @param length The length of the data object
     */
    public void init(byte[] buffer, short offset, short length) {
        dataPtr[0] = buffer;
        context[CONTEXT_POSITION] = offset;
        context[CONTEXT_POSITION_RESET] = offset;
        context[CONTEXT_LENGTH] = length;
    }

    /**
     * Clears any active TLV object being read
     */
    public void clear() {
        dataPtr[0] = null;

        context[CONTEXT_POSITION] = 0;
        context[CONTEXT_POSITION_RESET] = 0;
        context[CONTEXT_LENGTH] = 0;
    }

    /**
     * Tests whether there is a TLV object initialised for reading
     * @return true if there is a TLV object initialised for reading
     */
    public boolean isInitialized() {
        return (dataPtr[0] != null);
    }

    /**
     * Restores the current position to the offset originally supplied to init()
     */
    public void resetPosition() {
        if (!isInitialized()) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        context[CONTEXT_POSITION] = context[CONTEXT_POSITION_RESET];
    }

    /**
     * Finds a tag in the currently active TLV object
     * @param tag The tag to find
     * @return True if the requested tag was found before the end of the buffer was reached
     */
    public boolean find (byte tag) {
        while ((short)(context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET]) < context[CONTEXT_LENGTH]) {
            // Is this our tag number?
            if (tag == getTag()) return true;

            // Skip to the next tag at this level (i.e. it will not descend into children)
            if (!moveNext()) return false;
        }

        // We didn't find the requested tag;
        return false;
    }

    /**
     * Finds a tag in the currently active TLV object
     * @param tag The tag to find
     * @return True if the requested tag was found before the end of the buffer was reached
     */
    public boolean find(short tag) {
        while ((short)(context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET]) < context[CONTEXT_LENGTH]) {
            // Is this our tag number?
            if (tag == getTagShort()) return true;

            // Skip to the next tag at this level (i.e. it will not descend into children)
            if (!moveNext()) return false;
        }

        // We didn't find the requested tag;
        return false;
    }

    /**
     * Finds a tag in the currently active TLV object, not including the current tag
     * @param tag The tag to find
     * @return True if the requested tag was found before the end of the buffer was reached
     */
    public boolean findNext(byte tag) {
        // Skip to the next tag
        if (!moveNext()) return false;

        return find(tag);
    }

    /**
     * Finds a tag in the currently active TLV object, not including the current tag
     * @param tag The tag to find
     * @return True if the requested tag was found before the end of the buffer was reached
     */
    public boolean findNext(short tag) {
        // Skip to the next tag
        if (!moveNext()) return false;

        return find(tag);
    }

    /**
     * Moves to the next tag
     * @return True if the move was successful, or False if the buffer was overrun
     */
    public boolean moveNext() {
        // Skip to the next tag
        short dataLength = getLength();
        context[CONTEXT_POSITION] = getDataOffset();
        context[CONTEXT_POSITION] += dataLength;
        return ((short)(context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET] ) < context[CONTEXT_LENGTH]);
    }

    /**
     * Moves to the first tag inside the current tag
     * @return True if the move was successful, or False if the buffer was overrun
     */
    public boolean moveInto() {
        context[CONTEXT_POSITION] = getDataOffset();
        return ((short)(context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET] ) < context[CONTEXT_LENGTH]);
    }

	/**
	 * Tests if the current tag matches the supplied one
     * @param tag The tag to find
	 * @return True if the current tag matches the supplied one
	 */
    public boolean match(byte tag) {
        byte[] data = (byte[])dataPtr[0];
        return (tag == data[context[CONTEXT_POSITION]]);
    }

	/**
	 * Tests if the current tag matches the supplied one
     * @param tag The tag to find
	 * @return True if the current tag matches the supplied one
	 */
    private boolean match(short tag) {
        return (tag == Util.getShort((byte[])dataPtr[0], context[CONTEXT_POSITION]));
    }

    /**
     * Returns the tag identifier for the current tag
     * @return The identifier for the current tag
     */
    public byte getTag() {
        byte[] data = (byte[])dataPtr[0];
        return data[context[CONTEXT_POSITION]];
    }

    /**
     * Returns the tag identifier for the current tag
     * @return The identifier for the current tag
     */
    public short getTagShort() {
        return Util.getShort((byte[])dataPtr[0], context[CONTEXT_POSITION]);
    }

    /**
     * Returns true if the current tag is a constructed tag (has children)
     * @return True if the current tag is constructed
     */
    public boolean isConstructed() {
        return ((getTag() & MASK_CONSTRUCTED) == MASK_CONSTRUCTED);
    }

    /**
     * Gets the length of the current tag's data element
     * @return The length of the current tag's data element
     */
    public short getLength() {
        return getLength((byte[])dataPtr[0], context[CONTEXT_POSITION]);
    }

    /**
     * Returns the length of the data element for the tag found at offset
     * @param data The data to search
     * @param offset The offset of the tag to read
     * @return The length of the data element
     */
    public static short getLength(byte[] data, short offset) {

        // Skip the TAG element (always 1 byte in PIVTLV)
        offset++;

        // Is this a short-form length byte?
        if ((data[offset] & MASK_LONG_LENGTH) != MASK_LONG_LENGTH) {
            // short-form length
            return (short)(data[offset] & 0xFF);
        }

        // Is there more than 1 byte?
        if ((data[offset] & MASK_LENGTH) == 1) {
            // Values 0-255
            offset++;
            return (short)(data[offset] & 0xFF);
        } else if ((data[offset] & MASK_LENGTH) == 2) {
            // Values 0-65535
            // NOTE: Since we're assigning to a signed short, we don't
            // support anything greater than +32766.
            offset++;
            return Util.getShort(data, offset);
        } else {
            // We don't support multi-byte length definitions > 2
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return (short)-1; // Dummy for compiler
        }

    }

    /**
     * Returns true of the current tag has a zero-length (empty) data element
     * @return Whether the current tag has a zero length element
     */
    public boolean isNull() {
        return (getLength() == (short)0);
    }

    /**
     * Gets the current position within the TLV object
     * @return The current position within the TLV object
     */
    public short getOffset() {
        return context[CONTEXT_POSITION];
    }

    /**
     * Sets the current position within the TLV object
     * @param offset The current position within the TLV object
     */
    public void setOffset(short offset) {
        context[CONTEXT_POSITION] = offset;
    }

    /**
     * Gets the offset in the current tag to it's data element
     * @return The data offset in the current tag
     */
    public short getDataOffset() {
        return getDataOffset((byte[])dataPtr[0], context[CONTEXT_POSITION]);
    }

    /**
     * Gets the offset to the data element of the tag found at the requested offset
     * @param data The buffer containing the TLV object
     * @param offset The offset of the TLV element to inspect
     * @return The data element offset
     */
    public static short getDataOffset(byte[] data, short offset) {
        // Skip the TAG element (always 1 byte in PIVTLV)
        offset++;

        // Skip through the LENGTH element

        // Is this a long-form length byte?
        if ((data[offset] & MASK_LONG_LENGTH) == MASK_LONG_LENGTH) {
            // Skip the additional length bytes
            offset += (byte)(data[offset] & MASK_LENGTH);
        }
        offset++; // Skip the initial length byte

        return offset;
    }

    /**
     * Reads the current tag value as a short integer value
     * @return The current tagvalue  as a short integer
     */
    public short toShort() {
        byte[] data = (byte[])dataPtr[0];
        short length = getLength();
        short offset = getDataOffset();

        if ((short)1 == length) {
            return (short)(data[offset] & 0xFF);
        } else if ((short)2 == length) {
            return Util.getShort(data, offset);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            //TlvException.throwIt(TlvException.TAG_LENGTH_EXCEEDS_MAX);
            return (short)-1; // Dummy
        }
    }

    /**
     * Reads the current tag value as a byte value
     * @return The current tag value as a byte
     */
    public byte toByte() {
        byte[] data = (byte[])dataPtr[0];
        short length = getLength();

        if ((short)1 == length) {
            return data[getDataOffset()];
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            //TlvException.throwIt(TlvException.TAG_LENGTH_EXCEEDS_MAX);
            return (short)0; // Dummy
        }
    }

    /**
     * Writes the raw bytes for this tag to the specified buffer, which must have
     * enough space to write the entire object to (as per getLength()).
     * @param buffer The buffer to write the bytes to
     * @param offset The offset to start writing from in buffer
     */
    public void toBytes(byte[] buffer, short offset) {

        byte[] data = (byte[])dataPtr[0];
        short dataLength = getLength();
        short dataOffset = getDataOffset();

        Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, dataLength);
    }
}