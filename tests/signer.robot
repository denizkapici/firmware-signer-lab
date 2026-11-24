*** Settings ***
Documentation     Firmware behaviour on the simulated STM32F407 (UART4, PA0, PD12).
Resource          ${RENODEKEYWORDS}
Library           String
Library           Process
Suite Setup       Setup
Suite Teardown    Teardown
Test Setup        Prepare Signer
Test Teardown     Test Teardown

*** Variables ***
${ID_A}           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
${ID_B}           bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
${DIGEST_A}       aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
${DIGEST_B}       bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
${FIELDS_A}       ${ID_A} ${DIGEST_A} staging 1800000000
${FIELDS_B}       ${ID_B} ${DIGEST_B} production 1800000001
${SIGNATURE}      [0-9a-f]{128}
${COUNT}          [1-9][0-9]*
${KEYSTORE}       0x0800C000

*** Keywords ***
Prepare Signer
    Reset Emulation
    Execute Command    mach create "SignerLab"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    # Emulate a factory-blank chip: data sectors 2, 3 and 4 read 0xFF.
    Execute Command    sysbus LoadBinary @${CURDIR}/../firmware/build/blank-16k.bin 0x08008000
    Execute Command    sysbus LoadBinary @${CURDIR}/../firmware/build/blank-16k.bin 0x0800C000
    Execute Command    sysbus LoadBinary @${CURDIR}/../firmware/build/blank-64k.bin 0x08010000
    Execute Command    macro reset "sysbus LoadELF @${CURDIR}/../firmware/build/signer.elf"
    Execute Command    runMacro $reset
    Create Terminal Tester    sysbus.uart4    timeout=3    defaultPauseEmulation=true
    Start Emulation
    Wait For Line On Uart    ^INFO KEY_GENERATED$    treatAsRegex=true
    Wait For Line On Uart    ^INFO COUNTER 0$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true

Approve Request
    [Arguments]    ${fields}
    Send Command And Expect    REQUEST3 ${fields}    PENDING3 ${fields}
    Press Button After Debounce
    ${line}=    Wait For Line On Uart    ^APPROVED3 ${fields} ${COUNT} ${SIGNATURE}$    treatAsRegex=true
    ${counter}=    Evaluate    int($line.Line.split(" ")[5])
    RETURN    ${counter}

Read Device Public Key
    Write Line To Uart    PUBKEY    waitForEcho=false
    ${line}=    Wait For Line On Uart    ^PUBKEY [0-9a-f]{64}$    treatAsRegex=true
    ${key}=    Evaluate    $line.Line.split(" ")[1]
    Should Not Be Equal As Strings    ${key}    d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    RETURN    ${key}

Send Command And Expect
    [Arguments]    ${command}    ${response}
    Write Line To Uart    ${command}    waitForEcho=false
    Wait For Line On Uart    ^${response}$    treatAsRegex=true

LED State Should Be
    [Arguments]    ${expected}
    ${state}=    Execute Command    sysbus.gpioPortD.statusLed State
    ${state}=    Strip String    ${state}
    Should Be Equal As Strings    ${state}    ${expected}

Press Button After Debounce
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press

Release Button
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Release

Restart With Counter Log
    [Arguments]    ${image}    ${expected_counter}
    Execute Command    pause
    Execute Command    sysbus LoadBinary @${image} 0x08008000
    Execute Command    machine Reset
    Start Emulation
    Wait For Line On Uart    ^INFO KEY_LOADED$    treatAsRegex=true
    Wait For Line On Uart    ^INFO COUNTER ${expected_counter}$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true

Make Counter Log
    [Arguments]    @{arguments}
    ${directory}=    Evaluate    tempfile.mkdtemp(prefix="signer-counter-")    modules=tempfile
    ${image}=    Set Variable    ${directory}/counter.bin
    ${result}=    Run Process    %{SIGNER_HOST_PYTHON=python3}
    ...    ${CURDIR}/make_counter_log.py    ${image}    @{arguments}
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    RETURN    ${image}

Flash Word Should Be
    [Arguments]    ${address}    ${expected}
    ${word}=    Execute Command    sysbus ReadDoubleWord ${address}
    Should Be Equal As Integers    ${word.strip()}    ${expected}

*** Test Cases ***
PING Should Return PONG
    Send Command And Expect    PING    PONG

STATUS Should Return READY
    Send Command And Expect    STATUS    READY

Unknown Command Should Be Rejected
    Send Command And Expect    X    ERR UNKNOWN_COMMAND
    Send Command And Expect    PING    PONG

Removed V1 And V2 Requests Should Be Rejected
    Send Command And Expect    REQUEST A0000001 ${DIGEST_A}    ERR UNKNOWN_COMMAND
    Send Command And Expect    REQUEST2 ${FIELDS_A}    ERR UNKNOWN_COMMAND
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

LED Should Turn On And Off
    LED State Should Be    False
    Send Command And Expect    LED ON    OK LED ON
    LED State Should Be    True
    Send Command And Expect    LED OFF    OK LED OFF
    LED State Should Be    False

Button Should Report Press And Release
    Send Command And Expect    BUTTON    BUTTON RELEASED
    Execute Command    sysbus.gpioPortA.approveButton Press
    Send Command And Expect    BUTTON    BUTTON PRESSED
    Execute Command    sysbus.gpioPortA.approveButton Release
    Send Command And Expect    BUTTON    BUTTON RELEASED

255 Characters Should Be Accepted As A Complete Command
    ${command}=    Evaluate    "A" * 255
    Send Command And Expect    ${command}    ERR UNKNOWN_COMMAND
    Send Command And Expect    PING    PONG

256 Characters Should Be Rejected And Parser Should Recover
    ${command}=    Evaluate    "A" * 256
    Send Command And Expect    ${command}    ERR COMMAND_TOO_LONG
    Send Command And Expect    PING    PONG

Invalid Character Should Be Rejected And Parser Should Recover
    Execute Command    sysbus.uart4 WriteChar 0x00
    Execute Command    sysbus.uart4 WriteChar 0x0D
    Wait For Line On Uart    ^ERR INVALID_CHARACTER$    treatAsRegex=true
    Send Command And Expect    PING    PONG

SysTick Should Count Milliseconds Without UART Input
    ${address}=    Execute Command    sysbus GetSymbolAddress "system_milliseconds"
    ${address}=    Strip String    ${address}
    ${before}=    Execute Command    sysbus ReadDoubleWord ${address}
    Execute Command    emulation RunFor "0.100"
    ${after}=    Execute Command    sysbus ReadDoubleWord ${address}
    ${elapsed}=    Evaluate    (int($after.strip(), 0) - int($before.strip(), 0)) & 0xFFFFFFFF
    Log    Millisecond counter advanced by ${elapsed}
    Should Be True    95 <= ${elapsed} <= 105

Request Should Be Approved By A Fresh Button Press
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    LED State Should Be    True
    Press Button After Debounce
    Wait For Line On Uart    ^APPROVED3 ${FIELDS_A} ${COUNT} ${SIGNATURE}$    treatAsRegex=true
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

Approval Should Verify With The Device Public Key
    ${target}=    Evaluate    "x" * 32
    ${fields}=    Set Variable    ${ID_A} ${DIGEST_A} ${target} 9007199254740991
    ${public_key}=    Read Device Public Key
    Send Command And Expect    REQUEST3 ${fields}    PENDING3 ${fields}
    Press Button After Debounce
    ${line}=    Wait For Line On Uart    ^APPROVED3 ${fields} 1 ${SIGNATURE}$    treatAsRegex=true
    ${signature}=    Evaluate    $line.Line.split(" ")[-1]
    ${result}=    Run Process
    ...    %{SIGNER_HOST_PYTHON=python3}    ${CURDIR}/verify_signature.py
    ...    ${public_key}    ${ID_A}    ${DIGEST_A}    ${target}    9007199254740991    1
    ...    ${signature}
    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0
    Should Be Equal As Strings    ${result.stdout.strip()}    SIGNATURE OK

First Boot Should Generate A Key That Survives Reset
    ${first}=    Read Device Public Key
    Execute Command    machine Reset
    Start Emulation
    Wait For Line On Uart    ^INFO KEY_LOADED$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true
    ${second}=    Read Device Public Key
    Should Be Equal As Strings    ${first}    ${second}
    ${magic}=    Execute Command    sysbus ReadDoubleWord ${KEYSTORE}
    Should Be Equal As Integers    ${magic.strip()}    0x59454B53

Corrupted Key Record Should Block Signing And Not Be Replaced
    Read Device Public Key
    Execute Command    pause
    # Flip one byte of the stored seed directly in flash.
    Execute Command    sysbus WriteByte 0x0800C010 0x5A
    Execute Command    machine Reset
    Start Emulation
    Wait For Line On Uart    ^WARN KEY_CORRUPT$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true
    Send Command And Expect    PUBKEY    ERR NO_KEY
    Send Command And Expect    REQUEST3 ${FIELDS_A}    ERR NO_KEY
    LED State Should Be    False
    Send Command And Expect    STATUS    READY
    # The record is kept for inspection, not silently regenerated.
    ${magic}=    Execute Command    sysbus ReadDoubleWord ${KEYSTORE}
    Should Be Equal As Integers    ${magic.strip()}    0x59454B53
    ${byte}=    Execute Command    sysbus ReadByte 0x0800C010
    Should Be Equal As Integers    ${byte.strip()}    0x5A

Held Button Should Require Release And Another Press
    Execute Command    sysbus.gpioPortA.approveButton Press
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Execute Command    emulation RunFor "0.050"
    Send Command And Expect    STATUS    WAITING_APPROVAL
    Execute Command    sysbus.gpioPortA.approveButton Release
    Press Button After Debounce
    Wait For Line On Uart    ^APPROVED3 ${FIELDS_A} ${COUNT} ${SIGNATURE}$    treatAsRegex=true
    LED State Should Be    False

Short Button Pulse Should Not Approve
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Press Button After Debounce
    Execute Command    emulation RunFor "0.005"
    Execute Command    sysbus.gpioPortA.approveButton Release
    Execute Command    emulation RunFor "0.030"
    Send Command And Expect    STATUS    WAITING_APPROVAL
    Send Command And Expect    CANCEL    CANCELLED3 ${FIELDS_A}

Pending Request Should Reject Replacement And Allow Cancellation
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Send Command And Expect    REQUEST3 ${FIELDS_B}    ERR BUSY
    Send Command And Expect    LED OFF    ERR BUSY
    LED State Should Be    True
    Send Command And Expect    CANCEL    CANCELLED3 ${FIELDS_A}
    LED State Should Be    False
    Send Command And Expect    STATUS    READY
    Send Command And Expect    CANCEL    ERR NO_PENDING_REQUEST

Second Request Must Not Replace Pending Fields
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Send Command And Expect    REQUEST3 ${FIELDS_B}    ERR BUSY
    Press Button After Debounce
    Wait For Line On Uart    ^APPROVED3 ${FIELDS_A} ${COUNT} ${SIGNATURE}$    treatAsRegex=true

New Request After Cancellation Should Use New Fields
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Send Command And Expect    CANCEL    CANCELLED3 ${FIELDS_A}
    Send Command And Expect    REQUEST3 ${FIELDS_B}    PENDING3 ${FIELDS_B}
    Press Button After Debounce
    Wait For Line On Uart    ^APPROVED3 ${FIELDS_B} ${COUNT} ${SIGNATURE}$    treatAsRegex=true

Request Should Timeout Without UART Input
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Wait For Line On Uart    ^TIMEOUT3 ${FIELDS_A}$    timeout=6    treatAsRegex=true
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

Malformed Requests Should Be Rejected
    Send Command And Expect    REQUEST3    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ABC ${DIGEST_A} staging 1800000000    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${ID_A} abc staging 1800000000    ERR INVALID_REQUEST
    ${upper}=    Evaluate    "A" * 64
    Send Command And Expect    REQUEST3 ${ID_A} ${upper} staging 1800000000    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${ID_A} ${DIGEST_A} _staging 1800000000    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${ID_A} ${DIGEST_A} staging 01800000000    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${ID_A} ${DIGEST_A} staging 9007199254740992    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${FIELDS_A} extra    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST3 ${ID_A} ${DIGEST_A} staging    ERR INVALID_REQUEST
    LED State Should Be    False
    Send Command And Expect    PING    PONG

Request Length Limits Should Preserve Parser Recovery
    ${command}=    Evaluate    "REQUEST3 " + "x" * 246
    Send Command And Expect    ${command}    ERR INVALID_REQUEST
    ${command}=    Evaluate    "REQUEST3 " + "x" * 247
    Send Command And Expect    ${command}    ERR COMMAND_TOO_LONG
    Send Command And Expect    PING    PONG

Command Sent During Signing Should Not Be Lost
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Press Button After Debounce
    # The press is accepted after the 20 ms debounce; send PING just after
    # that, so its bytes arrive while the signature is being computed.
    Execute Command    emulation RunFor "0.022"
    Write Line To Uart    PING    waitForEcho=false
    Wait For Line On Uart    ^APPROVED3 ${FIELDS_A} ${COUNT} ${SIGNATURE}$    treatAsRegex=true
    Wait For Line On Uart    ^PONG$    treatAsRegex=true

Watchdog Should Not Reset An Idle Device
    Execute Command    emulation RunFor "6.0"
    Send Command And Expect    PING    PONG

Fault Should Be Reported And Recovered By Watchdog
    # Place a permanently undefined Thumb instruction (UDF #0) in RAM and jump to it.
    Execute Command    pause
    Execute Command    sysbus WriteWord 0x2001F000 0xDE00
    Execute Command    cpu PC 0x2001F000
    Start Emulation
    Wait For Line On Uart    ^FAULT pc=2001f000 .*$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    timeout=6    treatAsRegex=true
    Send Command And Expect    PING    PONG

Counter Should Increase Once Per Approval And Survive Reset
    Send Command And Expect    COUNTER    COUNTER 0
    ${first}=    Approve Request    ${FIELDS_A}
    Should Be Equal As Integers    ${first}    1
    Release Button
    ${second}=    Approve Request    ${FIELDS_B}
    Should Be Equal As Integers    ${second}    2
    Send Command And Expect    COUNTER    COUNTER 2
    Execute Command    machine Reset
    Start Emulation
    Wait For Line On Uart    ^INFO COUNTER 2$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true
    Release Button
    ${third}=    Approve Request    ${FIELDS_A}
    Should Be Equal As Integers    ${third}    3
    # Log entries: (1, ~1), (2, ~2), (3, ~3) at the start of sector 2.
    Flash Word Should Be    0x08008000    1
    Flash Word Should Be    0x08008004    0xFFFFFFFE
    Flash Word Should Be    0x08008010    3

Cancelled And Timed Out Requests Should Not Use The Counter
    Send Command And Expect    REQUEST3 ${FIELDS_A}    PENDING3 ${FIELDS_A}
    Send Command And Expect    CANCEL    CANCELLED3 ${FIELDS_A}
    Send Command And Expect    REQUEST3 ${FIELDS_B}    PENDING3 ${FIELDS_B}
    Wait For Line On Uart    ^TIMEOUT3 ${FIELDS_B}$    timeout=6    treatAsRegex=true
    Send Command And Expect    COUNTER    COUNTER 0
    Flash Word Should Be    0x08008000    0xFFFFFFFF

Full Counter Sector Should Continue In The Other Sector
    # 16 KB / 8 bytes = 2048 entries: sector 2 is completely full.
    ${image}=    Make Counter Log    1    2048
    Restart With Counter Log    ${image}    2048
    ${counter}=    Approve Request    ${FIELDS_A}
    Should Be Equal As Integers    ${counter}    2049
    Flash Word Should Be    0x08010000    2049
    Flash Word Should Be    0x08010004    0xFFFFF7FE
    Execute Command    machine Reset
    Start Emulation
    Wait For Line On Uart    ^INFO COUNTER 2049$    treatAsRegex=true
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true

Torn Counter Entry Should Be Ignored And Skipped
    # Entries 1..2, then an entry with a wrong complement (interrupted write).
    ${image}=    Make Counter Log    1    2    torn
    Restart With Counter Log    ${image}    2
    ${counter}=    Approve Request    ${FIELDS_A}
    Should Be Equal As Integers    ${counter}    3
    # Written after the torn slot, never on top of it.
    Flash Word Should Be    0x08008010    0x7FFFFFFF
    Flash Word Should Be    0x08008018    3
