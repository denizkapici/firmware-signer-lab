*** Settings ***
Documentation     Secure bootloader: slot A is started only with a valid signature.
Resource          ${RENODEKEYWORDS}
Library           Process
Library           OperatingSystem
Suite Setup       Boot Suite Setup
Suite Teardown    Boot Suite Teardown
Test Teardown     Test Teardown

*** Variables ***
${BUILD}          ${CURDIR}/../firmware/build
${SLOT_A}         0x08020000
${CODE}           0x08020200

*** Keywords ***
Boot Suite Setup
    Setup
    ${directory}=    Evaluate    tempfile.mkdtemp(prefix="signer-boot-")    modules=tempfile
    Set Suite Variable    ${WORK}    ${directory}

Boot Suite Teardown
    Teardown
    Remove Directory    ${WORK}    recursive=True

Create Board
    [Documentation]    Blank chip with the bootloader; slot A content is up to the test.
    Reset Emulation
    Execute Command    mach create "SignerLab"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    Execute Command    sysbus LoadBinary @${BUILD}/blank-16k.bin 0x08008000
    Execute Command    sysbus LoadBinary @${BUILD}/blank-16k.bin 0x0800C000
    Execute Command    sysbus LoadBinary @${BUILD}/blank-64k.bin 0x08010000
    Execute Command    sysbus LoadBinary @${BUILD}/blank-64k.bin 0x08020000
    Execute Command    sysbus LoadBinary @${BUILD}/blank-64k.bin 0x08030000
    Execute Command    macro reset "sysbus LoadELF @${BUILD}/bootloader.elf"
    Execute Command    runMacro $reset
    Create Terminal Tester    sysbus.uart4    timeout=3    defaultPauseEmulation=true

Load Slot A
    [Arguments]    ${image}=${BUILD}/signer-slot-a.bin
    Execute Command    sysbus LoadBinary @${image} ${SLOT_A}

Boot Should Stop With
    [Arguments]    ${status}
    Start Emulation
    Wait For Line On Uart    ^BOOT SLOT A ${status}$    treatAsRegex=true
    Wait For Line On Uart    ^BOOT HALT$    treatAsRegex=true
    Should Not Start Application

Should Not Start Application
    Test If Uart Is Idle    1

Run Signer Lab
    [Arguments]    @{arguments}
    ${result}=    Run Process    ${CURDIR}/../scripts/signer-lab    @{arguments}
    Log    ${result.stdout}
    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    RETURN    ${result}

Flip Byte
    [Arguments]    ${address}
    ${value}=    Execute Command    sysbus ReadByte ${address}
    ${flipped}=    Evaluate    int($value.strip(), 0) ^ 0x01
    Execute Command    sysbus WriteByte ${address} ${flipped}

*** Test Cases ***
Valid Image Should Boot The Application
    Create Board
    Load Slot A
    Start Emulation
    Wait For Line On Uart    ^BOOT signer-lab bootloader$    treatAsRegex=true
    Wait For Line On Uart    ^BOOT SLOT A OK version=1$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true
    Write Line To Uart    PING    waitForEcho=false
    Wait For Line On Uart    ^PONG$    treatAsRegex=true

Changed Code Byte Should Be Refused
    Create Board
    Load Slot A
    Flip Byte    0x08020600
    Boot Should Stop With    BAD_SIGNATURE

Changed Version In Header Should Be Refused
    Create Board
    Load Slot A
    # image_version is signed: raising it must invalidate the image.
    Execute Command    sysbus WriteDoubleWord 0x0802000C 2
    Boot Should Stop With    BAD_SIGNATURE

Changed Signature Should Be Refused
    Create Board
    Load Slot A
    Flip Byte    0x08020050
    Boot Should Stop With    BAD_SIGNATURE

Image Signed With Another Key Should Be Refused
    Run Signer Lab    firmware    keygen    --out    ${WORK}/other.key
    Run Signer Lab    firmware    sign    ${BUILD}/signer.bin    --key    ${WORK}/other.key
    ...    --version    1    --out    ${WORK}/other-slot.bin
    Create Board
    Load Slot A    ${WORK}/other-slot.bin
    Boot Should Stop With    BAD_SIGNATURE

Empty Slot Should Be Reported
    Create Board
    Boot Should Stop With    EMPTY

Zero-Filled Slot Should Be Refused
    Create Board
    Execute Command    sysbus WriteDoubleWord ${SLOT_A} 0
    Boot Should Stop With    BAD_HEADER

Nonzero Reserved Header Byte Should Be Refused
    Create Board
    Load Slot A
    Execute Command    sysbus WriteByte 0x08020020 1
    Boot Should Stop With    BAD_HEADER

Oversized Image Length Should Be Refused Before Hashing
    Create Board
    Load Slot A
    # Larger than the 128 KB slot minus the header: never read past the slot.
    Execute Command    sysbus WriteDoubleWord 0x08020008 0x00020000
    Boot Should Stop With    BAD_SIZE

Correctly Signed Image With Bad Vectors Should Be Refused
    # A valid signature over an image whose entry point lies outside it.
    ${binary}=    Evaluate    __import__("struct").pack("<II", 0x20020000, 0x08000001) + bytes(56)
    Create Binary File    ${WORK}/bad-vectors.bin    ${binary}
    ${result}=    Run Process    %{SIGNER_HOST_PYTHON=python3}
    ...    ${CURDIR}/sign_unchecked.py    ${WORK}/bad-vectors.bin
    ...    %{FIRMWARE_SIGNING_KEY=${BUILD}/dev-firmware-signing.key}
    ...    ${WORK}/bad-vectors-slot.bin
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    Create Board
    Load Slot A    ${WORK}/bad-vectors-slot.bin
    Boot Should Stop With    BAD_VECTORS
