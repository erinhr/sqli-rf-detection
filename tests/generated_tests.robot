
*** Settings ***
Resource          ${CURDIR}/../resources/variables.resource
Resource          ${CURDIR}/../resources/auth_keywords.resource
Resource          ${CURDIR}/../resources/sqli_keywords.resource
Suite Setup       Initialize Suite
Suite Teardown    Finalize SQLi Report

*** Test Cases ***
GET /createdb [query:unused]
    Scan Endpoint For SQLi    GET|/createdb|query|unused|none|

GET /users/v1 [query:unused]
    Scan Endpoint For SQLi    GET|/users/v1|query|unused|none|

GET /users/v1/_debug [query:unused]
    Scan Endpoint For SQLi    GET|/users/v1/_debug|query|unused|none|

POST /users/v1/register [json:username]
    Scan Endpoint For SQLi    POST|/users/v1/register|json|username|none|

POST /users/v1/register [json:password]
    Scan Endpoint For SQLi    POST|/users/v1/register|json|password|none|

POST /users/v1/login [json:username]
    Scan Endpoint For SQLi    POST|/users/v1/login|json|username|none|

POST /users/v1/login [json:password]
    Scan Endpoint For SQLi    POST|/users/v1/login|json|password|none|

GET /books/v1 [query:unused]
    Scan Endpoint For SQLi    GET|/books/v1|query|unused|none|

POST /books/v1 [json:book_title]
    Scan Endpoint For SQLi    POST|/books/v1|json|book_title|none|

GET /books/v1/{book_title} [path:book_title]
    Scan Endpoint For SQLi    GET|/books/v1/{book_title}|path|book_title|bearer|

GET /me [query:unused]
    Scan Endpoint For SQLi    GET|/me|query|unused|bearer|

GET /users/v1/{username} [path:username]
    Scan Endpoint For SQLi    GET|/users/v1/{username}|path|username|none|

DELETE /users/v1/{username} [path:username]
    Scan Endpoint For SQLi    DELETE|/users/v1/{username}|path|username|bearer|

PUT /users/v1/{username}/email [json:email]
    Scan Endpoint For SQLi    PUT|/users/v1/{username}/email|json|email|bearer|

PUT /users/v1/{username}/password [json:password]
    Scan Endpoint For SQLi    PUT|/users/v1/{username}/password|json|password|bearer|
