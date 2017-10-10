/******************************************************************************
MIT License

OpenFIPS201 - Copyright (c) 2017 Kim O'Sullivan (Makina)

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

This software was commissioned by the Australian Department of Defence to
provide an open reference implementation for the Personal Identity Verification
standard (FIPS PUB 201-2 / NIST SP800-73-4) to the public.

BETA RELEASE - Please note that this is an initial release for evaluation
purposes to demonstrate the design and progress of this reference code.

Please provide any feedback to: piv@makina.com.au
******************************************************************************/

package com.makina.security.OpenFIPS201;

/**
 * Provides common functionality for all PIV objects (data and security)
 */
public abstract class PIVObject {

    protected byte[] header;

    // Linked list element
    public PIVObject nextObject;

    protected PIVObject(byte id, byte modeContact, byte modeContactless) {
        header = new byte[LENGTH_HEADER];

        header[HEADER_ID] = id;
        header[HEADER_MODE_CONTACT] = modeContact;
        header[HEADER_MODE_CONTACTLESS] = modeContactless;
    }


    protected static final short HEADER_ID 					= (short)0;
    protected static final short HEADER_MODE_CONTACT		= (short)1;
    protected static final short HEADER_MODE_CONTACTLESS	= (short)2;

    // We allocate some spare header space for derived attributes
    protected static final short LENGTH_HEADER 				= (short)8;

    /**
     * Compares the requested identifier value to the current object's id
     */
    public boolean match(byte id) {
        return (header[HEADER_ID] == id);
    }

    /**
     * Returns the current object's identifier value
     */
    public byte getId() {
        return header[HEADER_ID];
    }

    /**
     * Returns the ACCESS MODE conditions for the contact interface
     */
    public byte getModeContact() {
        return header[HEADER_MODE_CONTACT];
    }

    /**
     * Returns the ACCESS MODE conditions for the contactless interface
     */
    public byte getModeContactless() {
        return header[HEADER_MODE_CONTACTLESS];
    }

    /**
     * Returns true if the current object is initialised with it's intended value
     */
    public abstract boolean isInitialized();

    /**
     * Clears the current object's value
     */
    public abstract void clear();
}