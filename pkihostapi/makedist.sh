#!/bin/sh

TODAY=`date +%Y%m%d`
NAME=javacardsign-$TODAY

mkdir $NAME

cp -r lib $NAME

mkdir $NAME/applet

cp ../pkiapplet/bin/net/sourceforge/javacardsign/applet/javacard/applet.cap $NAME/applet

cp README.txt lgpl*.txt pkihost.bat pkihost.sh files/* $NAME

rm -rf `find $NAME -name ".svn"`

zip -r $NAME.zip $NAME

rm -rf $NAME


