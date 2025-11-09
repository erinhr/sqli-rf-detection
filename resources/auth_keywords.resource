*** Settings ***
Library     RequestsLibrary
Library     BuiltIn
Library     Collections
Resource    variables.resource

*** Keywords ***
Create API Session
    Create Session    vampi    ${BASE_URL}    headers=${HEADERS}
    Set Suite Variable    ${CURRENT_AUTH_SCHEME}    none

Ensure Authorized Session
    [Arguments]    ${scheme}=none    ${apikey_header}=${APIKEY_NAME}
    ${sch}=    Convert To Lowercase    ${scheme}
    IF    '${sch}'=='bearer'
        ${tok}=    Get Variable Value    ${TOKEN}    ${EMPTY}
        IF    '${tok}'=='${EMPTY}'
            _Login And Set Bearer Token
        END
        Set Suite Variable    ${CURRENT_AUTH_SCHEME}    bearer
    ELSE IF    '${sch}'=='apikey'
        _Set API Key Header    ${apikey_header}    ${APIKEY_VALUE}
        Set Suite Variable    ${CURRENT_AUTH_SCHEME}    apikey
    ELSE
        Set Suite Variable    ${CURRENT_AUTH_SCHEME}    none
    END

_Login And Set Bearer Token
    &{body}=    Create Dictionary    username=${USER}    password=${PASS}
    ${resp}=    POST On Session    vampi    ${LOGIN_EP}    json=${body}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    200

    # Parse JSON dengan aman
    ${json}=    Evaluate    json.loads(r'''${resp.text}''')    json

    ${token}=   Set Variable    ${EMPTY}
    ${has_auth}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${json}    auth_token
    IF    ${has_auth}
        ${token}=    Get From Dictionary    ${json}    auth_token
    ELSE
        ${has_acc}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${json}    access_token
        IF    ${has_acc}
            ${token}=    Get From Dictionary    ${json}    access_token
        ELSE
            ${has_tok}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${json}    token
            IF    ${has_tok}
                ${token}=    Get From Dictionary    ${json}    token
            ELSE
                ${has_jwt}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${json}    jwt
                IF    ${has_jwt}
                    ${token}=    Get From Dictionary    ${json}    jwt
                END
            END
        END
    END

    # Kalau tetap kosong, fail dengan pesan yang membantu
    Run Keyword Unless    '${token}'!=''    Fail    Login sukses (200) tetapi tidak ada token di respons. Field yang dicari: auth_token / access_token / token / jwt. Body: ${resp.text}

    Set Suite Variable    ${TOKEN}    ${token}

    &{hd}=      Copy Dictionary    ${HEADERS}
    Set To Dictionary    ${hd}    Authorization=Bearer ${TOKEN}
    Update Session    vampi    headers=${hd}

_Set API Key Header
    [Arguments]    ${name}    ${value}
    &{hd}=    Copy Dictionary    ${HEADERS}
    Set To Dictionary    ${hd}    ${name}=${value}
    Update Session    vampi    headers=${hd}

GET Authorized
    [Arguments]    ${endpoint}    ${params}=${None}    ${headers}=${None}
    ${resp}=    GET On Session    vampi    ${endpoint}    params=${params}    headers=${headers}    expected_status=any
    ${scheme}=  Get Variable Value    ${CURRENT_AUTH_SCHEME}    none
    IF    ${resp.status_code}==401 and '${scheme}'=='bearer'
        _Login And Set Bearer Token
        ${resp}=    GET On Session    vampi    ${endpoint}    params=${params}    headers=${headers}    expected_status=any
    END
    RETURN    ${resp}

POST Authorized
    [Arguments]    ${endpoint}    ${json}=${None}    ${params}=${None}    ${headers}=${None}
    ${resp}=    POST On Session    vampi    ${endpoint}    json=${json}    params=${params}    headers=${headers}    expected_status=any
    ${scheme}=  Get Variable Value    ${CURRENT_AUTH_SCHEME}    none
    IF    ${resp.status_code}==401 and '${scheme}'=='bearer'
        _Login And Set Bearer Token
        ${resp}=    POST On Session    vampi    ${endpoint}    json=${json}    params=${params}    headers=${headers}    expected_status=any
    END
    RETURN    ${resp}

PUT Authorized
    [Arguments]    ${endpoint}    ${json}=${None}    ${params}=${None}    ${headers}=${None}
    ${resp}=    PUT On Session    vampi    ${endpoint}    json=${json}    params=${params}    headers=${headers}    expected_status=any
    ${scheme}=  Get Variable Value    ${CURRENT_AUTH_SCHEME}    none
    IF    ${resp.status_code}==401 and '${scheme}'=='bearer'
        _Login And Set Bearer Token
        ${resp}=    PUT On Session    vampi    ${endpoint}    json=${json}    params=${params}    headers=${headers}    expected_status=any
    END
    RETURN    ${resp}

DELETE Authorized
    [Arguments]    ${endpoint}    ${params}=${None}    ${headers}=${None}
    ${resp}=    DELETE On Session    vampi    ${endpoint}    params=${params}    headers=${headers}    expected_status=any
    ${scheme}=  Get Variable Value    ${CURRENT_AUTH_SCHEME}    none
    IF    ${resp.status_code}==401 and '${scheme}'=='bearer'
        _Login And Set Bearer Token
        ${resp}=    DELETE On Session    vampi    ${endpoint}    params=${params}    headers=${headers}    expected_status=any
    END
    RETURN    ${resp}

