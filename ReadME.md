#libmyradclient: a simple client library for radius protocol.

@author: qudreams

The library is from free-radius.you can find a detailed document at following websit:
    www.freeradius.org

The library just support 5 authentication methods as the following:
    PAP,CHAP,MSCHAP,MSCHAPV2,EAP-MD5

##Usage:
    you can compile the library use following directive:
        make
    after that,you can find a file that named libmyradclient.a;
    this is a static library of radius client library,
    you can link it into your radius program.

    There is a example in the source file example.c,you can use the following directive to generate it:
        make example
    Note:
        The example depends on libmyradclient.a,so you must compile radius client library first.
    


