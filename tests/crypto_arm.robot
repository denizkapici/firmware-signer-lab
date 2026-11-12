*** Settings ***
Resource          ${RENODEKEYWORDS}
Library           String
Suite Setup       Setup
Suite Teardown    Teardown
Test Teardown     Test Teardown

*** Test Cases ***
Ed25519 RFC Vector And Rejection Checks Should Pass On Cortex M4
    Reset Emulation
    Execute Command    mach create "CryptoTest"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    Execute Command    sysbus LoadELF @${CURDIR}/../firmware/build/crypto-test.elf
    Execute Command    emulation RunFor "2.0"
    ${address}=    Execute Command    sysbus GetSymbolAddress "crypto_test_result"
    ${address}=    Strip String    ${address}
    ${result}=    Execute Command    sysbus ReadDoubleWord ${address}
    Log    Crypto result bitmask: ${result}
    Should Be Equal As Integers    ${result}    31
