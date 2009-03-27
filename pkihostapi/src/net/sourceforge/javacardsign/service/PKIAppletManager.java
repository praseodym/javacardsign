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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CardTerminalListener;

/**
 * Manages PKI card insertions and removals.
 * 
 */
public class PKIAppletManager {
    private enum CardType {
        OTHER_CARD, PKI_CARD
    };

    private static final PKIAppletManager INSTANCE = new PKIAppletManager();

    private Map<CardService, CardType> cardTypes;

    private Map<CardService, PKIService> pkiServices;

    private Collection<PKIAppletListener> listeners;

    private PKIAppletManager() {
        cardTypes = new Hashtable<CardService, CardType>();
        pkiServices = new Hashtable<CardService, PKIService>();
        listeners = new ArrayList<PKIAppletListener>();
        final CardManager cm = CardManager.getInstance();
        cm.addCardTerminalListener(new CardTerminalListener() {

            public void cardInserted(CardEvent ce) {
                notifyCardEvent(ce);
                CardService service = ce.getService();
                try {
                    PKIService pkiService = new PKIService(service);
                    pkiService.open(); /* Selects applet... */
                    cardTypes.put(service, CardType.PKI_CARD);
                    pkiServices.put(service, pkiService);
                    final PKIAppletEvent pe = new PKIAppletEvent(
                            PKIAppletEvent.INSERTED, pkiService);
                    notifyPKIAppletEvent(pe);
                } catch (CardServiceException cse) {
                    cardTypes.put(service, CardType.OTHER_CARD);
                }
            }

            public void cardRemoved(CardEvent ce) {
                notifyCardEvent(ce);
                CardService service = ce.getService();
                CardType cardType = cardTypes.remove(service);
                if (cardType != null && cardType == CardType.PKI_CARD) {
                    PKIService pkiService = pkiServices.get(service);
                    final PKIAppletEvent pe = new PKIAppletEvent(
                            PKIAppletEvent.REMOVED, pkiService);
                    notifyPKIAppletEvent(pe);
                }
            }
        });
    }

    public synchronized void addPKIAppletListener(PKIAppletListener l) {
        listeners.add(l);
    }

    public synchronized void removePKIAppletListener(PKIAppletListener l) {
        listeners.remove(l);
    }

    public static PKIAppletManager getInstance() {
        return INSTANCE;
    }

    private void notifyCardEvent(final CardEvent ce) {
        for (final CardTerminalListener l : listeners) {
            (new Thread(new Runnable() {
                public void run() {
                    switch (ce.getType()) {
                    case CardEvent.INSERTED:
                        l.cardInserted(ce);
                        break;
                    case CardEvent.REMOVED:
                        l.cardRemoved(ce);
                        break;
                    }
                }
            })).start();
        }
    }

    private void notifyPKIAppletEvent(final PKIAppletEvent pe) {
        for (final PKIAppletListener l : listeners) {
            (new Thread(new Runnable() {
                public void run() {
                    switch (pe.getType()) {
                    case PKIAppletEvent.INSERTED:
                        l.pkiAppletInserted(pe);
                        break;
                    case PKIAppletEvent.REMOVED:
                        l.pkiAppletRemoved(pe);
                        break;
                    }
                }
            })).start();
        }
    }
}
