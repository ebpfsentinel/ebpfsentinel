#!/bin/sh
# l7-late-http-responder.sh - answers every HTTP/1.1 request on the
# connection one second after its request line, keeping the connection open.
# The second leaves room for the L7 verdict to reach the datapath. An answer
# written before the verdict lands can still pass - the documented limit of a
# refusal decided on a copy of the payload - so suite 29 asserts what happens
# once the verdict is in.
while IFS= read -r line; do
    case "$line" in
        GET*|POST*)
            sleep 1
            printf 'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: keep-alive\r\n\r\nanswered'
            ;;
    esac
done
