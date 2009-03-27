#!/bin/sh

TODAY=`date +%Y%m%d`
NAME=javacardsign-$TODAY

mkdir $NAME

cp -r lib files $NAME

mkdir $NAME/applet

cp ../pkiapplet/bin/net/sourceforge/javacardsign/applet/javacard/applet.cap $NAME/applet

cp -r README.txt lgpl*.txt pkihost.bat pkihost.sh $NAME

rm -rf `find $NAME -name ".svn"`

zip -r $NAME.zip $NAME

rm -rf $NAME


