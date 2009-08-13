INTRODUCTION
============

This is the current release of the Java Card PKI host API and
application. For more details see http://javacardsign.sourceforge.net.
This project has been developed by Wojciech Mostowski <woj@cs.ru.nl>
from the Digital Security group of Radboud University Nijmegen, the
Netherlands.

REQUIREMENTS
============

To run the host application you need Java Runtime Environment 1.6. To
load the applet to a Java Card smart card you need a Java Card and
Global Platform compliant applet loader, e.g. gpshell from
http://globalplatform.sourceforge.net. The best blank card to use is
NXP JCOP41. Whatever card you use it needs to support the following
Java Card API/crypto:

  ALG_RSA_SHA_PKCS1, ALG_RSA_NOPAD, ALG_SHA, ALG_SECURE_RANDOM,
  TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_1024.


SOURCE CODE, LICENSE
====================

The source code is released under LGPL and is currently only available
from the sourceforge SVN repository, see

https://sourceforge.net/scm/?type=svn&group_id=257447

The libraries that we use are released under respective licenses 
described in the "lib" folder.

RUNNING
=======

Unpack the release file (you must have done that already since you are
reading this file).

To run the host application go to the "lib" folder in your
terminal/prompt window and type (on Windows you can also double click
on the file):

  java -jar pkihost.jar
  
Or you can simply run either pkihost.sh or pkihost.bat depending on
your operating system.

To load the applet to the card use your applet loader program (e.g.
gpshell) to load applet.cap to the card.

CURRENT STATE AND LIMITATIONS
=============================

The software in the project implements the following:

 * An ISO7816 compliant Java Card PKI applet. The compliance is
   attempted to be preserved for the personalised state of the applet.
   This means that the personalisation commands do not necessarily
   follow the ISO standard or take high security requirements into
   account. The overall characteristics of the applet is the
   following:

    - The applet stores three user certificates, one CA certificate
      that was used to sign user certificates, and three corresponding
      user private keys: for authentication, signing, and decryption.
      These keys are used with signing, decrypting, and authentication
      APDU commands: PSO (Perform Security Operation), and Internal
      Authenticate, see ISO7816.

    - The applet also implements an ISO7816 file system. It is up to
      the host to initialise this file system with according PKI file
      structure. Currently the applet does not return the FCI
      information on file selection. 

    - The crypto routines on the applet are limited to RSA PKCS#15 and
      PSS ciphers with keys of length 1024. The signing command
      expects a SHA1 or SHA256 object encoded according to ASN.1
      rules. The decryption command decrypts any valid RSA PKCS#15
      block, the internal authentication command encrypts any data
      within the limits of the used key length and PKCS#15 padding
      limitations. * An ISO7816 host API for talking to ISO7816
      compliant PKI applets and personalising our applet.

 * A GUI for personalising our above mentioned PKI applet and for
   using any ISO7816 compliant applet. Note: currently the GUI
   application only reads out and can use our own PKI applet. It does
   not yet make an attempt to parse the information included in the
   ISO7816-15 compliant files, like EF.CIAInfo, EF.OD, etc. For now it
   assumes that it talks to our PKI applet personalised by the GUI. 


SHORT USER MANUAL
=================

Creating a PKI card
-------------------

To write new data and personalise a fresh PKI applet:

 * Run the host application, see above

 * Insert a card with a fresh PKI applet into your reader. The card
   has to be inserted into the contact interface.

 * Fill in the data in the first tab (Private Init). The PUC has to be
   16 bytes long. Setting the historical bytes of the ATR is optional.
   You need to load the four certificates and three private keys. You can
   use the ones provided in the "files" folder. Then click Initialize Applet.
   All the required data will be written to the applet.

 * Next go to user administration panel. Here you can set a new user
   PIN. It has to be between 4 and 20 digits long. Click Set PIN, you
   will be asked to enter your PUC. Here you can also perform user PIN
   verification with the card at any time.

 * The applet is ready to be used (personalised). 

Batch Creating a PKI card
-------------------------

It is also possible to upload all the required data to the PKI card
from a ZIP file. To do this run:

  java -jar pkihost.jar batch <zipfile>
  
Once a PKI card is detected in the card terminal the data from the
ZIP files is written to the card. The ZIP file should contain
the following files:

  - puc.txt - the PUC for the card
  - pin.txt - the PIN for the card
  - authkeyid.bin, deckeyid.bin, signkeyid.bin - correponding key
    identifiers
  - authkey.der, deckey.der, signkey.der - corresponding private
    keys in PKCS8/der format
  - cacert.der, authcert.der, deccert.der, signcert.der - 
    corresponding certificates in X509/der format
  - (optional) historical.bin - the historical bytes for the card
  
The files folder contains an example of a valid ZIP file.


Reading out a PKI card
----------------------

To read out and use the PKI card:

 * Run the host application

 * Insert the PKI card into the reader (contact interface).

 * In the certificates tab you can load all the certificates from the
   card. This is necessary to perform cryptographics operations later
   on. The user certificates in our PKI applet are protected by a PIN,
   you will be asked for one.

 * In the "Decrypt" tab you can decrypt any data. You enter the cipher
   text (or create it with "Encrypt text..."/"Encrypt file...", the
   card's decryption certificate key will be used for encryption).
   Then press the Decrypt button. You will be asked for a PIN and the
   card will decrypt the data, which will appear in the "Result" box.

 * The "Signature & Authentication" tab works in a similar way. Data
   to be signed or encrypted is entered in a corresponding box. The
   signing/encryption algorithm can be configured with the radio
   buttons. The Sign button will do the required cryptograhic
   operation on the card after asking for the PIN. The result will
   appear in the "Signature" box. Here you can also verify the
   signature with using the card's certificate. Just press Verify.

 * The "Challenge" tab can be used at any point to prompt the PKI card
   for a challenge. This challenge can be used as a data to be signed
   in the signature tab. 

Creating Certificates
---------------------

(Thanks to Ronan Le Meillat for this section)

For testing can use your own certificates for example with openssl
 
 * CA Self-signed Creation
	openssl req -new -newkey rsa:2048 -keyout cakey.pem -nodes -out cacert.csr
	openssl x509 -req -days 1200 -in cacert.csr -signkey cakey.pem -out cacert.pem

 * Keys creation
	openssl genrsa 1024 > authkey.pem
	openssl genrsa 1024 > signkey.pem
	openssl genrsa 1024 > deckey.pem

 * Requests creation
	openssl req -new -nodes -key authkey.pem -out authcert.csr
	openssl req -new -nodes -key signkey.pem -out signcert.csr
	openssl req -new -nodes -key deckey.pem -out deccert.csr

 * Certificates signing
	openssl x509 -req -CAcreateserial -CA cacert.pem -CAkey cakey.pem -in authcert.csr -out authcert.pem
	openssl x509 -req -CAcreateserial -CA cacert.pem -CAkey cakey.pem -in signcert.csr -out signcert.pem
	openssl x509 -req -CAcreateserial -CA cacert.pem -CAkey cakey.pem -in deccert.csr -out deccert.pem

 * Certificates conversion
	openssl x509 -in cacert.pem -outform der -out cacert.der
	openssl x509 -in authcert.pem -outform der -out authcert.der
	openssl x509 -in signcert.pem -outform der -out signcert.der
	openssl x509 -in deccert.pem -outform der -out deccert.der

 * Keys conversion
	openssl pkcs8 -topk8 -in authkey.pem -nocrypt -outform der -out authkey.der
	openssl pkcs8 -topk8 -in signkey.pem -nocrypt -outform der -out signkey.der
	openssl pkcs8 -topk8 -in deckey.pem -nocrypt -outform der -out deckey.der
	
You now have authkey.der/authcert.der signkey.der/signcert.der deckey.der/deccert.der and cacert.der
