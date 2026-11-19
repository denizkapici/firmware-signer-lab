*** Settings ***
Documentation     End to end: host CLI <-> PTY <-> simulated firmware.
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
${HOST_DIR}       ${CURDIR}/../host
${FIRMWARE}       ${CURDIR}/../firmware/build/signer.bin

*** Keywords ***
Prepare Direct UART
    ${directory}=    Evaluate    tempfile.mkdtemp(prefix="signer-direct-")    modules=tempfile
    Set Test Variable    ${PTY_DIR}    ${directory}
    Reset Emulation
    Execute Command    mach create "SignerLab"
    Execute Command    machine LoadPlatformDescription @${CURDIR}/../simulation/signer.repl
    Execute Command    macro reset "sysbus LoadELF @${CURDIR}/../firmware/build/signer.elf"
    Execute Command    runMacro $reset
    Execute Command    emulation CreateUartPtyTerminal "direct_uart" "${PTY_DIR}/uart"
    Execute Command    connector Connect sysbus.uart4 direct_uart
    Execute Command    sysbus.gpioPortA.approveButton Release
    Execute Command    emulation RunFor "0.010"
    ${binary}=    Get Binary File    ${FIRMWARE}
    ${digest}=    Evaluate    hashlib.sha256($binary).hexdigest()    modules=hashlib
    Set Test Variable    ${FILE_DIGEST}    ${digest}

Run Signer CLI
    [Arguments]    @{arguments}
    ${result}=    Run Process
    ...    %{SIGNER_HOST_PYTHON=python3}    -m    signer_lab    @{arguments}
    ...    env:PYTHONPATH=${HOST_DIR}    timeout=20 seconds    on_timeout=kill
    Log    ${result.stdout}
    Log    ${result.stderr}
    RETURN    ${result}

Start Approval
    [Arguments]    ${request_id}
    Set Test Variable    ${ACTIVE_ID}    ${request_id}
    ${process}=    Start Process
    ...    %{SIGNER_HOST_PYTHON=python3}    -m    signer_lab    approve    ${FIRMWARE}
    ...    --port    ${PTY_DIR}/uart
    ...    --database    ${PTY_DIR}/approvals.sqlite3
    ...    --target    staging
    ...    --request-id    ${request_id}
    ...    --timeout    60
    ...    --receipt-out    ${PTY_DIR}/approval.json
    ...    --allow-demo-key
    ...    env:PYTHONPATH=${HOST_DIR}
    ...    stdout=${PTY_DIR}/client.stdout
    ...    stderr=${PTY_DIR}/client.stderr
    Set Test Variable    ${CLIENT_PROCESS}    ${process}
    Wait Until Keyword Succeeds    10 seconds    50 milliseconds    Client Has Sent Request
    Advance Until Pending

Client Has Sent Request
    ${output}=    Get File    ${PTY_DIR}/client.stdout
    Should Contain    ${output}    Sent: REQUEST2 ${ACTIVE_ID} ${FILE_DIGEST} staging

Advance Until Pending
    FOR    ${index}    IN RANGE    40
        Execute Command    emulation RunFor "0.050"
        Sleep    20 milliseconds
        ${output}=    Get File    ${PTY_DIR}/client.stdout
        ${pending}=    Run Keyword And Return Status
        ...    Should Contain    ${output}    PENDING: waiting for button approval.
        IF    ${pending}    RETURN
    END
    Fail    Host client did not receive PENDING2.

Cleanup Direct UART
    Run Keyword And Continue On Failure    Terminate All Processes    kill=True
    Run Keyword And Continue On Failure    Test Teardown
    Run Keyword And Continue On Failure    Reset Emulation
    IF    $PTY_DIR != ""
        Remove Directory    ${PTY_DIR}    recursive=True
    END

*** Test Cases ***
Approval Should Produce A Receipt That Is Accepted Only Once
    ${id}=    Evaluate    "a" * 32
    Remove File    ${CURDIR}/../firmware/build/approval-demo.json
    Start Approval    ${id}
    Execute Command    emulation RunFor "0.030"
    Execute Command    sysbus.gpioPortA.approveButton Press
    Execute Command    emulation RunFor "1.000"
    ${result}=    Wait For Process    ${CLIENT_PROCESS}    timeout=10 seconds    on_timeout=kill
    Log    ${result.stdout}
    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0
    Should Be Empty    ${result.stderr}
    Should Contain    ${result.stdout}    ACCEPTED2 ${id} ${FILE_DIGEST} staging
    Should Contain    ${result.stdout}    verified with the DEMO KEY
    File Should Exist    ${PTY_DIR}/approval.json

    # Remove the simulated device: everything below is host-only.
    Reset Emulation

    ${verify}=    Run Signer CLI    verify    ${FIRMWARE}
    ...    --receipt    ${PTY_DIR}/approval.json    --target    staging    --allow-demo-key
    Should Be Equal As Integers    ${verify.rc}    0
    Should Contain    ${verify.stdout}    VALID ${id} ${FILE_DIGEST} staging

    ${replay}=    Run Signer CLI    accept    ${FIRMWARE}
    ...    --receipt    ${PTY_DIR}/approval.json
    ...    --database    ${PTY_DIR}/approvals.sqlite3
    ...    --target    staging    --allow-demo-key
    Should Be Equal As Integers    ${replay.rc}    1
    Should Contain    ${replay.stderr}    already consumed
    Should Not Contain    ${replay.stdout}    ACCEPTED2

    Copy File    ${PTY_DIR}/approval.json    ${CURDIR}/../firmware/build/approval-demo.json

Firmware Timeout Should Not Consume Approval
    ${id}=    Evaluate    "b" * 32
    Start Approval    ${id}
    Execute Command    emulation RunFor "5.100"
    ${result}=    Wait For Process    ${CLIENT_PROCESS}    timeout=10 seconds    on_timeout=kill
    Log    ${result.stdout}
    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    2
    Should Be Empty    ${result.stderr}
    Should Contain    ${result.stdout}    NOT ACCEPTED: TIMEOUT2
    Should Not Contain    ${result.stdout}    ACCEPTED2 ${id}
    File Should Not Exist    ${PTY_DIR}/approval.json

    ${check}=    Run Process
    ...    %{SIGNER_HOST_PYTHON=python3}
    ...    ${CURDIR}/check_pending_approval.py
    ...    ${PTY_DIR}/approvals.sqlite3
    Should Be Equal As Integers    ${check.rc}    0
    Should Be Empty    ${check.stderr}
