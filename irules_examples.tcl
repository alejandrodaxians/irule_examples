# WWW REDIRECT:
when HTTP_REQUEST {
    if {[HTTP::host] starts_with "example.com"} {
        HTTP::redirect https://WWW.example.com[HTTP::uri]
    }
}


# HTTP REDIRECT:
when HTTP_REQUEST {
    if {[HTTP::uri] contains <string>} {
        HTTP::redirect https://[HTTP::host][HTTP::uri]
    }
}


# URI Pool Selection:
when HTTP_REQUEST {
    if {[HTTP::uri] ends_with "string"} {
        pool PoolName
    } { pool PoolAlternative }
}


# SWITCH:
when HTTP_REQUEST {
    switch -glob [HTTP::host] {
        example-url1 {pool PoolName1}
        example-url2 [pool PoolName2]
        example-url3 {pool PoolName3}
        default {pool PoolDefault}
    }
}


# SNAT:
when CLIENT_ACCEPTED {
    if {[TCP::local_port] == 8181 and [class match [IP::client_addr] equals net-group]} {
        snat <ip>
    } else {
        forward
    }
}


# Insert Header:
when HTTP_REQUEST {
    HTTP::header insert SOURCE_IP [IP::remote_addr]
}


# Create random hashed HTTP Session ID:
when HTTP_REQUEST {
    set id "[IP::client_addr][TCP::client_port][IP::local_addr][TCP::local_port][expr {int(10000000000*rand())}]"
    binary scan [md5 $id] H* md5var junk
    HTTP::header insert X-SESSIONID $md5var
}


# SSL Server side on DataGroup:
when LB_SELECTED {
    SSL::disable serverside
    if  {[class_match [LB::server_add] equals poolmember-group]} {
        SSL::enable_serverside
    }
}


# Troubleshooting and logging (Log File is /var/log/ltm):
when HTTP_REQUEST {
    set CLIENT_ADDR [IP::client_addr]
    set XFF [HTTP::header X-forwarded-For]
    set ID "[TCP::local_port] [exor {int(1000000000*rand())}]"
    set REQUEST_RECEIVE [clock clicks -milliseconds]
}

when HTTP_REQUEST_SEND {
    set REQUEST_SEND [clock clicks -milliseconds]
    set REQUEST_WAIT [EXPR {$REQUEST_SEND - $REQUEST_RECEIVE}]
    log local0. "SRC:$CLIENT_ADDR SFF:$XFF ID:$ID"
}

when HTTP_RESPONSE {
    set RESPONSE_TIME [expr {[clock click -milliseconds] - $REQUEST_SEND}]
    log local0. "SRC:$CLIENT_ADDR XFF:$XFF ID:$ID - HTTP[HTTP::status] $RESPONSE_TIME\ms/$REQUEST_WAIT\ms [LB::server_addr]"
}