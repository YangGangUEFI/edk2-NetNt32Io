#/*++
#
# Copyright (c) 2006 - 2016, Intel Corporation                                                         
# All rights reserved. This program and the accompanying materials                          
# are licensed and made available under the terms and conditions of the BSD License         
# which accompanies this distribution.  The full text of the license may be found at        
# http://opensource.org/licenses/bsd-license.php                                            
#                                                                                          
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED. 
# 
#  Module Name:
#
#    makefile
#
#  Abstract:
#
#    Makefile for the SNPNT32IO library.
#


#
#WINPCAP_DIR is the directory that contains the WinPcap developer's package
#The TARGET can be either DEBUG or RELEASE. Adapt these two directives to your need
#The ARCH can be either IA32 or X64. Adapt these two directives to your need
#
!IF "$(PCAP)" == "NPCAP"
WINPCAP_DIR = ".\npcap"
!ELSE
WINPCAP_DIR = ".\WpdPack"
!ENDIF
TARGET      = DEBUG
ARCH        = IA32

#
#WINPCAP_LIBPATH is the directory that contains the WinPcap developer's library
#
!IF "$(ARCH)" == "IA32"
WINPCAP_LIB = "$(WINPCAP_DIR)\Lib"
!ELSE
WINPCAP_LIB = "$(WINPCAP_DIR)\Lib\x64"
!ENDIF

#
#Change the output directory and compile parameters according to the TARGET.
#
!IF "$(TARGET)" == "DEBUG"
OUTPUT_DIR  = Debug_$(ARCH)
C_DEFINES   = /D "WIN32" /D "SNPNT32IO_EXPORTS"
C_FLAGS     = /Od /FD /MTd /Fo"$(OUTPUT_DIR)/" /Fd"$(OUTPUT_DIR)/vc70" /W3 /c /Wp64 /ZI /TC 
LINK_FLAGS  = /DLL /DEBUG /PDB:"$(OUTPUT_DIR)/SnpNt32Io.pdb"
!ELSE
OUTPUT_DIR  = Release_$(ARCH)
C_DEFINES   = /D "WIN32" /D "NDEBUG" /D "SNPNT32IO_EXPORTS" 
C_FLAGS     = /O2 /FD /MT /GS /Fo"$(OUTPUT_DIR)/" /Fd"$(OUTPUT_DIR)/vc70" /W3 /c /Wp64 /Zi /TC 
LINK_FLAGS  = /DLL
!ENDIF


#
#Main section to build the SnpNt32Io.DLL. The "-" before command prevents the
#nmake to exit when the command returns an error 
#
SnpNt32Io.DLL : SnpNt32Io.obj
 link $(LINK_FLAGS) /IMPLIB:"$(OUTPUT_DIR)/SnpNt32Io.lib" /LIBPATH:$(WINPCAP_LIB)\
	  /OUT:"$(OUTPUT_DIR)/SnpNt32Io.dll" wpcap.lib packet.lib $(OUTPUT_DIR)/SnpNt32Io.obj
  
SnpNt32Io.obj : src\SnpNt32Io.c
 - md $(OUTPUT_DIR)
 cl   /I $(WINPCAP_DIR)\Include $(C_DEFINES) $(C_FLAGS) src\SnpNt32Io.c

#
#Rules to clean the build up, it just deletes the output directory and everything under it
#
clean:
 - rd /S /Q $(OUTPUT_DIR)
