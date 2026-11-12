*** Settings ***
Resource          ${RENODEKEYWORDS}
Library           Process
Library           OperatingSystem
Suite Setup       Setup
Suite Teardown    Teardown
Test Setup        Prepare Direct UART
Test Teardown     Cleanup Direct UART
Test Timeout      90 seconds

*** Variables ***
${PTY_DIR}        ${EMPTY}

*** Keywords ***
Prepare Direct UART
    ${directory}=    Evaluate    tempfile.mkdtemp(prefix="signer-direct-")    modules=tempfile
    Set Test Variable    ${PTY_DIR}    ${directory}
    Reset Emulation
    Execute Command    mach create "SignerLab"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    Execute Command    sysbus LoadELF @${CURDIR}/../firmware/build/signer.elf
    Execute Command    emulation CreateUartPtyTerminal "direct_uart" "${PTY_DIR}/uart"
    Execute Command    connector Connect sysbus.uart4 direct_uart
    Execute Command    sysbus.gpioPortA.approveButton Release
    Execute Command    emulation RunFor "0.010"
    ${binary}=    Get Binary File    ${CURDIR}/../firmware/build/signer.bin
    ${digest}=    Evaluate    hashlib.sha256($binary).hexdigest()    modules=hashlib
    Set Test Variable    ${FILE_DIGEST}    ${digest}

Start Direct Client
    [Arguments]    ${request_id}
    Set Test Variable    ${ACTIVE_ID}    ${request_id}
    ${process}=    Start Process
    ...    %{SIGNER_HOST_PYTHON=python3}
    ...    ${CURDIR}/../scripts/signer-client.py
    ...    ${CURDIR}/../firmware/build/signer.bin
    ...    --request-id    ${request_id}
    ...    --port    ${PTY_DIR}/uart
    ...    --timeout    60
    ...    --receipt-out    ${PTY_DIR}/approval.json
    ...    stdout=${PTY_DIR}/client.stdout
    ...    stderr=${PTY_DIR}/client.stderr
    Set Test Variable    ${CLIENT_PROCESS}    ${process}
    Wait Until Keyword Succeeds    10 seconds    50 milliseconds    Client Has Sent Request
    Advance Until Pending

Client Has Sent Request
    ${output}=    Get File    ${PTY_DIR}/client.stdout
    Should Contain    ${output}    Gonderildi: REQUEST ${ACTIVE_ID} ${FILE_DIGEST}

Advance Until Pending
    FOR    ${index}    IN RANGE    40
        Execute Command    emulation RunFor "0.050"
        Sleep    20 milliseconds
        ${output}=    Get File    ${PTY_DIR}/client.stdout
        ${pending}=    Run Keyword And Return Status
        ...    Should Contain    ${output}    PENDING: buton onayi bekleniyor.
        IF    ${pending}
            RETURN
        END
    END
    Fail    Direct client did not receive PENDING.

Check Client Result
    [Arguments]    ${expected_status}    ${expected_code}
    ${result}=    Wait For Process    ${CLIENT_PROCESS}    timeout=10 seconds    on_timeout=kill
    Log    ${result.stdout}
    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    ${expected_code}
    Should Be Empty    ${result.stderr}
    Should Contain    ${result.stdout}    Alindi: ${expected_status} ${ACTIVE_ID} ${FILE_DIGEST}
    RETURN    ${result}

Cleanup Direct UART
    Run Keyword And Continue On Failure    Terminate All Processes    kill=True
    Run Keyword And Continue On Failure    Test Teardown
    Run Keyword And Continue On Failure    Reset Emulation
    IF    $PTY_DIR != ""
        Remove Directory    ${PTY_DIR}    recursive=True
    END

*** Test Cases ***
Direct Python Client Should Receive Approval
    Start Direct Client    D0000001
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Execute Command    emulation RunFor "0.100"
    ${result}=    Check Client Result    APPROVED    0
    Should Contain    ${result.stdout}    Ed25519 imzasi DEMO anahtariyla dogrulandi.
    Execute Command    sysbus.gpioPortA.approveButton Release
    File Should Exist    ${PTY_DIR}/approval.json
    Should Contain    ${result.stdout}    Onay belgesi kaydedildi:

    # Remove the simulated device before offline verification.
    Reset Emulation
    ${verification}=    Run Process
    ...    %{SIGNER_HOST_PYTHON=python3}
    ...    ${CURDIR}/../scripts/signer-client.py
    ...    ${CURDIR}/../firmware/build/signer.bin
    ...    --verify-receipt    ${PTY_DIR}/approval.json
    ...    timeout=10 seconds
    ...    on_timeout=kill
    Log    ${verification.stdout}
    Log    ${verification.stderr}
    Should Be Equal As Integers    ${verification.rc}    0
    Should Be Empty    ${verification.stderr}
    Should Contain    ${verification.stdout}    Dosya ozeti ve Ed25519 imzasi dogrulandi: DEMO ANAHTARI.

Direct Python Client Should Receive Firmware Timeout
    Start Direct Client    D0000002
    Execute Command    emulation RunFor "5.100"
    ${result}=    Check Client Result    TIMEOUT    2
    Should Not Contain    ${result.stdout}    Eslesen APPROVED yaniti alindi
    File Should Not Exist    ${PTY_DIR}/approval.json
