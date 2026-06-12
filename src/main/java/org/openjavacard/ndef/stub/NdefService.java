/*
 * openjavacard-ndef: JavaCard applet implementing an NDEF tag
 * Copyright (C) 2015-2018 Ingo Albrecht <copyright@promovicz.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

package org.openjavacard.ndef.stub;

import javacard.framework.Shareable;

public interface NdefService extends Shareable {
    byte[] getData();
}
