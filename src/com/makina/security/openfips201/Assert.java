package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public final class Assert {
  private Assert() {
    // Private constructor to prevent instantiation
  }

  public static void isTrue(boolean value) throws ISOException {
    if (!value) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isFalse(boolean value) throws ISOException {
    if (value) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isEqual(boolean value1, boolean value2) throws ISOException {
    if (value1 != value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isEqual(byte value1, byte value2) throws ISOException {
    if (value1 != value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isEqual(short value1, short value2) throws ISOException {
    if (value1 != value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isEqual(Object value1, Object value2) throws ISOException {
    if (value1 == null || value2 == null || value1 != value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNotEqual(boolean value1, boolean value2) throws ISOException {
    if (value1 == value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNotEqual(byte value1, byte value2) throws ISOException {
    if (value1 == value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNotEqual(short value1, short value2) throws ISOException {
    if (value1 == value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNotEqual(Object value1, Object value2) throws ISOException {
    if (value1 == null || value2 == null || value1 == value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNull(Object value) {
    if (value != null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isNotNull(Object value) {
    if (value == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isReferenceEqual(byte[] value1, byte[] value2) throws ISOException {
    if (value1 == null || value2 == null || value1 != value2) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void isArrayEqual(byte[] value1, byte[] value2) throws ISOException {
    if (value1 == null
        || value2 == null
        || value1.length != value2.length
        || Util.arrayCompare(value1, (short) 0, value2, (short) 0, (short) value1.length)
            != (short) 0) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }
}
