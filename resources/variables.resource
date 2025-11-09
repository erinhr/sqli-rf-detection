*** Settings ***
Library     BuiltIn
Library     Collections
Library     OperatingSystem

*** Variables ***
# ===== Defaults yang aman (boleh di-override via env/CLI) =====
${BASE_URL}            http://localhost:5002
${LOGIN_EP}            /users/v1/login
${CREATE_DB_EP}        /createdb
${TIME_THRESHOLD}      3.0
${FAIL_ON_MISS}       ${False}
${VULN_FAILS_TEST}    ${False}    # set ${True} jika mau test FAIL ketika ada kerentanan
${INCLUDE_UNUSED}     ${False}
@{ROUTER_ERRORS}   Unexpected path    Cannot GET    Route not found    NotFoundError


${USER}                admin
${PASS}                pass1

${APIKEY_NAME}         X-API-Key
${APIKEY_VALUE}        ${EMPTY}

${RUN_TECHNIQUES}      error,boolean,time,union
${INCLUDE_UNUSED}      ${False}

${ENDPOINTS_FILE}      ${EXECDIR}/data/endpoints.txt
${PAYLOADS_FILE}       ${EXECDIR}/data/sql_injection_payloads.csv

# Baseline payloads untuk masing-masing lokasi input
${BASELINE_QUERY}      normal
${BASELINE_PATH}       normal
${BASELINE_JSON}       normal

&{HEADERS}             Content-Type=application/json
@{SQL_ERRORS}          SQL syntax     sqlite error     MySQL server     you have an error in your SQL
&{DEFAULT_JSON_BODIES}
...    /users/v1/register={"email":"demos@gmail.com","password":"demo","username":"erin"}
...    /users/v1/login={"password":"${PASS}","username":"${USER}"}
...    /books/v1={"book_title":"demo","secret":"demooo"}
...    /users/v1/{username}/email={"email":"demo@example.com"}
...    /users/v1/{username}/password={"password":"demo2"}

*** Keywords ***
Bootstrap Variables
    [Documentation]    Membaca environment/CLI overrides dan set sebagai Suite Variables TANPA inline IF.
    # --- BASE_URL ---
    ${env_base}=    Get Environment Variable    VAMPI_BASE_URL    ${EMPTY}
    IF    '${env_base}'!=''
        Set Suite Variable    ${BASE_URL}    ${env_base}
    END

    # --- Login creds ---
    ${env_user}=    Get Environment Variable    VAMPI_USER    ${EMPTY}
    IF    '${env_user}'!=''
        Set Suite Variable    ${USER}    ${env_user}
    END
    ${env_pass}=    Get Environment Variable    VAMPI_PASS    ${EMPTY}
    IF    '${env_pass}'!=''
        Set Suite Variable    ${PASS}    ${env_pass}
    END

    # --- API Key (opsional) ---
    ${env_key}=    Get Environment Variable    VAMPI_APIKEY    ${EMPTY}
    IF    '${env_key}'!=''
        Set Suite Variable    ${APIKEY_VALUE}    ${env_key}
    END

    # --- File endpoints & payloads (boleh override via env) ---
    ${env_eps}=    Get Environment Variable    VAMPI_ENDPOINTS_FILE    ${EMPTY}
    IF    '${env_eps}'!=''
        Set Suite Variable    ${ENDPOINTS_FILE}    ${env_eps}
    END
    ${env_pls}=    Get Environment Variable    VAMPI_PAYLOADS_FILE    ${EMPTY}
    IF    '${env_pls}'!=''
        Set Suite Variable    ${PAYLOADS_FILE}    ${env_pls}
    END

    # --- Teknik & flag ---
    ${cli_rt}=    Get Variable Value    ${RUN_TECHNIQUES}    error,boolean,time,union
    Set Suite Variable    ${RUN_TECHNIQUES}    ${cli_rt}
    ${cli_inc}=    Get Variable Value    ${INCLUDE_UNUSED}    ${False}
    Set Suite Variable    ${INCLUDE_UNUSED}    ${cli_inc}

    # --- Reset headers dasar ---
    &{h}=    Create Dictionary    Content-Type=application/json
    Set Suite Variable    &{HEADERS}    &{h}
