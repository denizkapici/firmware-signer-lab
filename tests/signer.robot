*** Settings ***
Resource          ${RENODEKEYWORDS}
Library           String
Suite Setup       Setup
Suite Teardown    Teardown
Test Setup        Prepare Signer
Test Teardown     Test Teardown

*** Variables ***
${REQUEST_ID}    A0000001
${OTHER_ID}      B0000002
${DIGEST_A}      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
${DIGEST_B}      bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

*** Keywords ***
Prepare Signer
    Reset Emulation
    Execute Command    mach create "SignerLab"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    Execute Command    sysbus LoadELF @${CURDIR}/../firmware/build/signer.elf
    Create Terminal Tester    sysbus.uart4    timeout=3    defaultPauseEmulation=true
    Start Emulation
    Wait For Line On Uart    ^Signer firmware started$    treatAsRegex=true

Send Command And Expect
    [Arguments]    ${command}    ${response}
    Write Line To Uart    ${command}    waitForEcho=false
    Wait For Line On Uart    ^${response}$    treatAsRegex=true

LED State Should Be
    [Arguments]    ${expected}
    ${state}=    Execute Command    sysbus.gpioPortD.statusLed State
    ${state}=    Strip String    ${state}
    Should Be Equal As Strings    ${state}    ${expected}

*** Test Cases ***
PING Should Return PONG
    Send Command And Expect    PING    PONG

STATUS Should Return READY
    Send Command And Expect    STATUS    READY

Unknown Command Should Be Rejected
    Send Command And Expect    X    ERR UNKNOWN_COMMAND
    Send Command And Expect    PING    PONG

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

127 Characters Should Be Accepted As A Complete Command
    ${command}=    Evaluate    "A" * 127
    Send Command And Expect    ${command}    ERR UNKNOWN_COMMAND
    Send Command And Expect    PING    PONG

128 Characters Should Be Rejected And Parser Should Recover
    ${command}=    Evaluate    "A" * 128
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
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    LED State Should Be    True
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Wait For Line On Uart    ^APPROVED ${REQUEST_ID} ${DIGEST_A}$    treatAsRegex=true
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

Held Button Should Require Release And Another Press
    Execute Command    sysbus.gpioPortA.approveButton Press
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Execute Command    emulation RunFor "0.050"
    Send Command And Expect    STATUS    WAITING_APPROVAL
    Execute Command    sysbus.gpioPortA.approveButton Release
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Wait For Line On Uart    ^APPROVED ${REQUEST_ID} ${DIGEST_A}$    treatAsRegex=true
    LED State Should Be    False

Pending Request Should Reject Another Request And Allow Cancellation
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Send Command And Expect    REQUEST ${OTHER_ID} ${DIGEST_B}    ERR BUSY
    Send Command And Expect    LED OFF    ERR BUSY
    LED State Should Be    True
    Send Command And Expect    CANCEL    CANCELLED ${REQUEST_ID} ${DIGEST_A}
    LED State Should Be    False
    Send Command And Expect    STATUS    READY
    Send Command And Expect    CANCEL    ERR NO_PENDING_REQUEST

Request Should Timeout Without UART Input
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Wait For Line On Uart    ^TIMEOUT ${REQUEST_ID} ${DIGEST_A}$    timeout=6    treatAsRegex=true
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

Short Button Pulse Should Not Approve
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Execute Command    emulation RunFor "0.005"
    Execute Command    sysbus.gpioPortA.approveButton Release
    Execute Command    emulation RunFor "0.030"
    Send Command And Expect    STATUS    WAITING_APPROVAL
    Send Command And Expect    CANCEL    CANCELLED ${REQUEST_ID} ${DIGEST_A}


Malformed Requests Should Be Rejected
    Send Command And Expect    REQUEST    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST ABC ${DIGEST_A}    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST Z0000001 ${DIGEST_A}    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST ${REQUEST_ID} abc    ERR INVALID_REQUEST
    ${bad_digest}=    Evaluate    "g" * 64
    Send Command And Expect    REQUEST ${REQUEST_ID} ${bad_digest}    ERR INVALID_REQUEST
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}0    ERR INVALID_REQUEST
    LED State Should Be    False
    Send Command And Expect    STATUS    READY
    Send Command And Expect    PING    PONG

Second Request Must Not Replace Pending Digest
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Send Command And Expect    REQUEST ${OTHER_ID} ${DIGEST_B}    ERR BUSY
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Wait For Line On Uart    ^APPROVED ${REQUEST_ID} ${DIGEST_A}$    treatAsRegex=true
    LED State Should Be    False
    Send Command And Expect    STATUS    READY

New Request After Cancellation Should Use New Digest
    Send Command And Expect    REQUEST ${REQUEST_ID} ${DIGEST_A}    PENDING ${REQUEST_ID} ${DIGEST_A}
    Send Command And Expect    CANCEL    CANCELLED ${REQUEST_ID} ${DIGEST_A}
    Send Command And Expect    REQUEST ${OTHER_ID} ${DIGEST_B}    PENDING ${OTHER_ID} ${DIGEST_B}
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Wait For Line On Uart    ^APPROVED ${OTHER_ID} ${DIGEST_B}$    treatAsRegex=true
    LED State Should Be    False
