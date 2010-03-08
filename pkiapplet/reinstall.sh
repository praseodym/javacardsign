#!/bin/bash
# re-install the applet to the card. You need gpj.jar.
java -jar gpj.jar -deletedeps -delete  A000000063 -list
java -jar gpj.jar -load bin/net/sourceforge/javacardsign/applet/javacard/applet.cap -install -list
