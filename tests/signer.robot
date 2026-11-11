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
