/*
 * Java Card PKI applet - ISO7816 compliant Java Card applet. 
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

package net.sourceforge.javacardsign.applet;

import javacard.framework.Util;
import javacard.framework.JCSystem;

final class FileSystem {

    final static short MASTER_FILE_ID = (short)0x3F00;
    final static byte PERM_FREE = 0;
    final static byte PERM_PIN = 1;

    private static final byte DIR = -1;
    
    private Object[] efFiles = null;
    private byte[] efPerms = null;
    private short totalFiles = 0;
    byte[] fileStructure = null;
    private short[] fileStructureIndex;

    FileNotFoundException fnfe;
    
    FileSystem(short maxFiles) {
        efFiles = new Object[maxFiles];
        efPerms = new byte[maxFiles];
        fileStructureIndex= JCSystem.makeTransientShortArray((short)1,
                JCSystem.CLEAR_ON_DESELECT);
        fnfe = new FileNotFoundException();
    }

    boolean createFile(short fid, short length, byte perm) {
        if(totalFiles == efFiles.length) {
            return false;
        }
        try{
        short index = searchId((short)0, fid);
        efFiles[totalFiles] = new byte[length];
        efPerms[totalFiles] = perm;
        fileStructure[index] = (byte)totalFiles;
        totalFiles++;
        return true;
        }catch(FileNotFoundException e) {
            return false;
        }
    }

    byte[] getCurrentFile(short index) {
        try{
        return (byte[])efFiles[index];
        }catch(ArrayIndexOutOfBoundsException aioobe) {
            return null;
        }
    }

    byte getPerm(short index) {
        return efPerms[index];
    }
    
    short getCurrentIndex() {
        short index = (short)(fileStructureIndex[0] - 1);
        if(index == -1) {
            return -1;
        }
        return fileStructure[index];
    }
    
    boolean selectEntryAbsolute(short id) {
        try {
          fileStructureIndex[0] = (short)(searchId((short)0, id) + 1);
          return true;
        }catch(FileNotFoundException fnfe) {
          return false;
        }
    }

    boolean selectEntryParent() {
        try {
        short index = (short)(fileStructureIndex[0] - 1);
        if(index == -1 || fileStructure[index] != DIR) {
            return false;
        }
        index = fileStructure[(short)(index + 1)];
        if(index == -1) {
            return false;
        }
        fileStructureIndex[0] = (short)(index + 1);
        return true;
        }catch(ArrayIndexOutOfBoundsException aioobe) {
            return false;
        }
    }

    boolean selectEntryUnderCurrent(short id, boolean ef) {
        short index = (short)(fileStructureIndex[0] - 1);
        if(index == -1) {
            return false;
        }
        try {
          index = findEntryRelative(index, id);
          if((fileStructure[index] != DIR) == ef) {
             fileStructureIndex[0] = (short)(index + 1);
             return true;
          }
        }catch(FileNotFoundException fnfe) {
        }
        return false; 
    }    

    boolean selectEntryByPath(byte[] path, short offset, short length, boolean master) {
        short index = master ? 0 : (short)(fileStructureIndex[0] - 1);
        if(index == -1) {
            return false;
        }
        try {
          index = findEntryPath(index, path, offset, length);
          fileStructureIndex[0] = (short)(index + 1);
          return true;
        }catch(FileNotFoundException fnfe) {
            return false;
        }
    }
    
    short findCurrentSFI(byte sfi) {
        try{
        short start = (short)(fileStructureIndex[0] - 1);
        if(start == -1 || fileStructure[start] != DIR) {
            return -1;
        }
        short childNum = fileStructure[(short)(start+4)];
        for(short i=0; i<childNum; i++) {
            short index = fileStructure[(short)(start + (short)(i + 5))];
            if(fileStructure[index] != DIR) {
               if(fileStructure[(short)(index + 4)] == sfi)
                   return index; 
            }            
        }
        }catch(ArrayIndexOutOfBoundsException aioobe) {
            
        }
        return -1;
    }
    
    private short findEntryRelative(short start, short id)
      throws FileNotFoundException {
        try{
        if(fileStructure[start] != DIR) {
            throw fnfe;
        }
        short childNum = fileStructure[(short)(start + 4)];
        
        for(short i = 0; i<childNum; i++) {
            short index = fileStructure[(short)(start + (short)(5 + i))];
            short fid = Util.getShort(fileStructure, (short)(index + 1));
            if(fid == id) {
               return index;
            }
        }
        }catch(ArrayIndexOutOfBoundsException aioobe) {
            
        }
        throw fnfe;        
    }

    private short findEntryPath(
            short start, byte[] path, short offset, short length)
      throws FileNotFoundException{
        try{
        if(length == 0) {
           return start;
        }
        short id = Util.makeShort(path[offset], path[(short)(offset+1)]);
        start = findEntryRelative(start, id);
        offset += 2;
        length = (short)(length - 2);
        return findEntryPath(start, path, offset, length);
        }catch(ArrayIndexOutOfBoundsException aioobe){
            throw fnfe;
        }
    }

    
    short searchId(short start, short id) throws FileNotFoundException{
        return searchId(this.fileStructure, (short)0, start, (short)this.fileStructure.length, id);
    }
    
    short searchId(byte[] fileStructureArray, short shift, short start, short lastOffset, short id) throws ArrayIndexOutOfBoundsException, FileNotFoundException{
       if(start < 0 || start > (short)(lastOffset - 5)) {
           // This sould produce ArrayIndexOutOfBoundsException
           fileStructureArray[fileStructureArray.length] = (byte)0xFF;
       }
       short fid = Util.getShort(fileStructureArray, (short)(start + 1));
       if(fid == id) {
           return start;
       }
       if(fileStructureArray[start] != DIR) {
           throw fnfe;
       }else{
           short childNum = fileStructureArray[(short)(start+4)];
           if(start > (short)((short)(lastOffset - 5) - childNum)) {
               fileStructureArray[fileStructureArray.length] = (byte)0xFF;
           }           
           for(short i=0; i< childNum; i++) {
               try {
                 return searchId(fileStructureArray, shift, (short)(fileStructureArray[(short)(start+(short)(5+i))] + shift), lastOffset, id);
               }catch(FileNotFoundException e) {                 
               }
           }
       }
       throw fnfe;
    }
}
