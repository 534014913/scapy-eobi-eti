# REAME
A generic framework on top of scapy for parsing/generation data from eobi/eti

## How to use Scapy to build packets
Custom protocol are created by extend the Packet class provided by scapy. There are
two fields required for each class `name` and `fields_desc`. name is the name of the protocol
displayed when useing `ls()`, `show()`, `show2()` to view the information of the packet. `fields_decs` is
the list of fileds of the protocol. *note: scapy does not report error message when
its `field_desc` instead of `fields_desc`*

### Scapy field type to actual field type.
Integer Fields: All the fields in eobi/eti are little endian
1bit int field: `ByteField(<name>, <default value>)`
2bit int field: `LEShortField(<name>, <default value>)`
4bit signed int field: `LESignedIntField(<name>, <default value>)`
4bit unsigned int field: `LEIntField(<name>, <default value>)`
8bit signed int field: `LESignedLongField(<name>, <default value>)`
8bit int field: `LELongField(<name>, <default value>)`

String Fields:
length 1: `ByteField(<name>, <default value>)`
length n: `StrFixedLenField(<name>, <default value>, <n>)`
*note: StrFixedLenField show be used instead of StrLenField*

Composite Fields:
only occur once: `PacketField(<name>, <default parameters, usually None>, <field packet class>)`
occur multiple times:`PacketListField(<name>, <default parameters, usually None>, <field packet class>)`

`<field packet class>`: defined like an ordinary Packet class with one additional function, `extract_padding()`

All Packet Classes with field `BodyLen` need to overload the function `post_build()`, this populate the field `BodyLen` with the length of the packet.

## How to use
### Generate protocol file
`> python3.9 eobi_code_generator -h` for help information
`-i`: path to input specification file e.g. spec/eobi/10_0/eobi.xml
`-o`: path to the output file, to stdout if not specified

### How to generate packets using the protocol files
import the generated protocol file
Refer to the examples in *`eobi_test.py`*

