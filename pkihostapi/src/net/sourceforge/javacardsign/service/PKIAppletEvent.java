/*
 * Java Card PKI host API - A Java API for accessing ISO7816
 * compliant PKI cards. 
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package net.sourceforge.javacardsign.service;

import java.util.EventObject;

/**
 * Event object use to notify clients about PKI card presence/absence changes.
 * 
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class PKIAppletEvent extends EventObject {
    public static final int REMOVED = 0, INSERTED = 1;

    private int type;

    private PKIService service;

    public PKIAppletEvent(int type, PKIService service) {
        super(service);
        this.type = type;
        this.service = service;
    }

    public int getType() {
        return type;
    }

    public PKIService getService() {
        return service;
    }

    public String toString() {
        switch (type) {
        case REMOVED:
            return "PKI applet removed from " + service;
        case INSERTED:
            return "PKI applet inserted in " + service;
        }
        return "CardEvent " + service;
    }

    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (other == this) {
            return true;
        }
        if (other instanceof PKIAppletEvent) {
            return false;
        }
        PKIAppletEvent otherCardEvent = (PKIAppletEvent) other;
        return type == otherCardEvent.type
                && service.equals(otherCardEvent.service);
    }
}
