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

/**
 * Provides functionality for PIV data objects, implementing an A/B buffer approach to
 * prevent data exposure on incomplete writes.
 *
 * <p>This class extends {@link PIVObject} to store and manage the content in a tear-safe manner.
 * It creates two potential buffers (A and B) and only switches to the newly written buffer once
 * finalisation has succeeded, thus preventing partial overwrites from exposing invalid data.
 */
final class PIVContainer extends PIVObject {

    /**
     * A persistent data object content array, used for the active buffer once finalised.
     */
    private byte[] contentA = null;

    /**
     * A persistent data object content array, used as a staging buffer for new content.
     */
    private byte[] contentB = null;

    /**
     * Reference to the currently active data buffer.
     */
    private byte[] contentPtr = null;

    /**
     * Index for the administration key in the extended header.
     */
    private static final short HEADER_ADMIN_KEY = (short) 2;

    /**
     * The total length of the extended header.
     */
    private static final short LENGTH_EXTENDED_HEADER = (short) 3;

    /**
     * Constructs a {@code PIVContainer} with the given identifiers.
     *
     * @param id              The data object identifier.
     * @param modeContact     The contact usage mode.
     * @param modeContactless The contactless usage mode.
     * @param adminKey        The administration key; if zero, the default key is used.
     */
    PIVContainer(int id, byte modeContact, byte modeContactless, byte adminKey) {
        super(id, modeContact, modeContactless);

        // If the administrative key is not specified, use the default (9B) key.
        if (adminKey == (byte) 0) {
            adminKey = Config.DEFAULT_ADMIN_KEY;
        }
        
        // If the PIN_ALWAYS access mode is set, always ensure that PIN is also set
        if ((header[HEADER_MODE_CONTACT] & ACCESS_MODE_IMMEDIATE) == ACCESS_MODE_IMMEDIATE) {
          header[HEADER_MODE_CONTACT] |= ACCESS_MODE_PIN;
        }
        if ((header[HEADER_MODE_CONTACTLESS] & ACCESS_MODE_IMMEDIATE) == ACCESS_MODE_IMMEDIATE) {
          header[HEADER_MODE_CONTACTLESS] |= ACCESS_MODE_PIN;
        }

        header[HEADER_ADMIN_KEY] = adminKey;
    }

    /**
     * Returns the length of the extended header specific to this object.
     *
     * @return The extended header length.
     */
    @Override
    protected short getHeaderLength() {
        return LENGTH_EXTENDED_HEADER;
    }

    @Override
    protected short getHeader(TLVWriter writer) {      
      // We write without a parent tag.
      writer.write(Constants.TAG_OBJECT_ID, id);
      writer.write(Constants.TAG_MODE_CONTACT, header[HEADER_MODE_CONTACT]);
      writer.write(Constants.TAG_MODE_CONTACTLESS, header[HEADER_MODE_CONTACTLESS]);
      writer.write(Constants.TAG_ADMIN_KEY, header[HEADER_ADMIN_KEY]);
      
      return writer.finish();
    }
    
    /**
     * Retrieves the administrative key.
     *
     * @return The administrative key byte stored in the header.
     */
    @Override
    byte getAdminKey() {
        return header[HEADER_ADMIN_KEY];
    }

    /**
     * Parses a 1-to-3 byte identifier from a buffer region into an integer.
     *
     * @param buffer The source buffer containing the identifier.
     * @param offset The starting offset within the buffer.
     * @param length The length of the identifier (1 to 3 bytes).
     * @return The integer representation of the identifier.
     * @throws ISOException If {@code length} is outside the range 1..3.
     */
    static int parseId(byte[] buffer, short offset, short length) {
        if (length < 1 || length > 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        int result = 0;
        for (short i = 0; i < length; i++) {
            result |= (buffer[offset] & 0xFF) << ((length - 1 - i) * 8);
            offset++;
        }
        return result;
    }

    /**
     * Retrieves the current content of this container.
     *
     * <p>If the container is not initialised, an exception is thrown.
     * If an alternate buffer is present (indicating a prior incomplete write), it is discarded.
     *
     * @return A reference to the currently active content buffer.
     * @throws ISOException If the container is not initialised.
     */
    public byte[] getContent() {
        if (!isInitialised()) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // If the alternate buffer is not null, we discard it to ensure no half-written data remains.
        if (contentPtr == contentA && contentB != null) {
            Platform.zeroise(contentB, (short) 0, (short) contentB.length);
            contentB = null;
            Platform.requestObjectDeletion();
        } else if (contentPtr == contentB && contentA != null) {
            Platform.zeroise(contentA, (short) 0, (short) contentA.length);
            contentA = null;
            Platform.requestObjectDeletion();
        }

        return contentPtr;
    }

    /**
     * Returns the number of bytes allocated in the active content buffer.
     *
     * @return The length of the active buffer, or 0 if uninitialised.
     */
    short getLength() {
        if (contentPtr == null) {
            return 0;
        } else {
            return (short) (contentPtr.length);
        }
    }

    /**
     * Allocates a new buffer for writing.
     *
     * <p>Implements an A/B system for tear prevention:
     * <ul>
     *   <li>If {@code contentPtr} is null or currently pointing to {@code contentB}, allocate {@code contentA}.
     *   <li>Otherwise, allocate {@code contentB}.
     * </ul>
     *
     * @param length The requested length for the new buffer.
     * @return A newly allocated byte array of the specified length.
     * @throws ISOException If the requested length is invalid (<= 0).
     */
    byte[] allocate(short length) throws ISOException {
        // PRE-CONDITION: The supplied length must be > 0
        if (length <= (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Decide which buffer to allocate based on the current pointer.
        if (contentPtr == null || contentPtr == contentB) {
            contentA = new byte[length];
            return contentA;
        } else {
            // contentPtr == contentA
            contentB = new byte[length];
            return contentB;
        }
    }

    /**
     * Finalises the new content, making it the active buffer.
     *
     * <p>When all writes are complete, this method is called to switch {@code contentPtr}
     * to the newly written buffer.
     *
     * @throws ISOException If this method is called without a matching allocate() call.
     */
    void finalise() {
        if (contentPtr == null || contentPtr == contentB) {
            // If contentA is null here, no successful allocate() was called.
            if (contentA == null) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            contentPtr = contentA;

            // Discard the other buffer if it exists.
            if (contentB != null) {
                Platform.zeroise(contentB, (short) 0, (short) contentB.length);
                contentB = null;
                Platform.requestObjectDeletion();
            }
        } else {
            // contentPtr == contentA
            if (contentB == null) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            contentPtr = contentB;

            // Discard the other buffer if it exists.
            if (contentA != null) {
                Platform.zeroise(contentA, (short) 0, (short) contentA.length);
                contentA = null;
                Platform.requestObjectDeletion();
            }
        }
    }

    /**
     * Indicates whether the object is currently populated with data.
     *
     * @return True if the object has an active content buffer, false otherwise.
     */
    @Override
    boolean isInitialised() {
        return (contentPtr != null);
    }

    /**
     * Wipes all data from this container.
     *
     * <p>If in FIPS-approved mode, zeroises the current active buffer before discarding.
     */
    @Override
    void clear() {
        // FIPS140 - Zeroise all objects first
        if (Config.FIPS_APPROVED_MODE && contentPtr != null) {
            Platform.zeroise(contentPtr, (short) 0, (short) contentPtr.length);
        }

        // Nullify references so they may be garbage-collected.
        contentPtr = null;
        contentA = null;
        contentB = null;

        Platform.requestObjectDeletion();
    }
}
