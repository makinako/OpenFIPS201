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

package com.makina.security.openfips201;

final class TLV {
  private TLV() {
    // Prevent instantiation
  }

  // Tag Class
  static final byte CLASS_UNIVERSAL = (byte) 0x00;
  static final byte CLASS_APPLICATION = (byte) 0x40;
  static final byte CLASS_CONTEXT = (byte) 0x80;
  static final byte CLASS_PRIVATE = (byte) 0xC0;

  // Length Constants
  static final short LENGTH_1BYTE = (short) 1;
  static final short LENGTH_2BYTE = (short) 2;
  static final short LENGTH_3BYTE = (short) 3;

  static final short LENGTH_1BYTE_MAX = (short) 0x7F;
  static final short LENGTH_2BYTE_MAX = (short) 0xFF;
  static final short LENGTH_3BYTE_MAX = (short) 0x7FFF;

  // Masks
  static final byte MASK_CONSTRUCTED = (byte) 0x20;
  static final byte MASK_LOW_TAG_NUMBER = (byte) 0x1F;
  static final byte MASK_HIGH_TAG_NUMBER = (byte) 0x7F;
  static final byte MASK_TAG_MULTI_BYTE = (byte) 0x1F;
  static final byte MASK_HIGH_TAG_MOREDATA = (byte) 0x80;
  static final byte MASK_LONG_LENGTH = (byte) 0x80;
  static final byte MASK_LENGTH = (byte) 0x7F;

  // Universal tags
  static final byte ASN1_BOOLEAN = (byte) 0x01;
  static final byte ASN1_INTEGER = (byte) 0x02;
  static final byte ASN1_BIT_STRING = (byte) 0x03;
  static final byte ASN1_OCTET_STRING = (byte) 0x04;
  static final byte ASN1_NULL = (byte) 0x05;
  static final byte ASN1_OBJECT = (byte) 0x06;
  static final byte ASN1_ENUMERATED = (byte) 0x0A;
  static final byte ASN1_SEQUENCE = (byte) 0x10; //  "Sequence" and "Sequence of"
  static final byte ASN1_SET = (byte) 0x11; //  "Set" and "Set of"
  static final byte ASN1_PRINT_STRING = (byte) 0x13;
  static final byte ASN1_T61_STRING = (byte) 0x14;
  static final byte ASN1_IA5_STRING = (byte) 0x16;
  static final byte ASN1_UTC_TIME = (byte) 0x17;

  // Type Values
  static final byte TRUE = (byte) 0xFF;
  static final byte FALSE = (byte) 0x00;
}
