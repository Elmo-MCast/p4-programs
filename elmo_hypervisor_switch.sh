# Add Elmo headers as a batch of bytes
ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0,priority=32768,ipv4__dstAddr=0x1234ABCD \
    actions=add_header:elmo_header, \
            set_field:0x112233441F2F3F4F5F6F223344551F2F->elmo_header_data, \
            deparse, \
            output:3"
