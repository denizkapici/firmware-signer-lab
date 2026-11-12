*** Settings ***
Resource          ${RENODEKEYWORDS}
Library           String
Suite Setup       Setup
Suite Teardown    Teardown
Test Setup        Prepare Signer
Test Teardown     Test Teardown

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

63 Characters Should Be Accepted As A Complete Command
    ${command}=    Evaluate    "A" * 63
    Send Command And Expect    ${command}    ERR UNKNOWN_COMMAND
    Send Command And Expect    PING    PONG

64 Characters Should Be Rejected And Parser Should Recover
    ${command}=    Evaluate    "A" * 64
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
