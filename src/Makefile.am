
CC	= @CC@

PCAPINC = @PCAPINC@
PCAPLIB = @PCAPLIB@


bin_PROGRAMS=dnsrob test-unbound test-pcap test-thread
dnsrob_SOURCES=dnsrob.c log.c thread.c dq_data.c
dnsrob_LDADD=$(PCAPLIB) $(UNBOUNDLIB) $(LNETLIB)

test_unbound_SOURCES=test_unbound.c
test_unbound_LDADD=$(UNBOUNDLIB)

test_pcap_SOURCES=test_pcap.c log.c
test_pcap_LDADD=$(PCAPLIB) $(LNETLIB)

test_thread_SOURCES=test_pthread.c thread.c log.c dq_data.c
test_thread_LDADD=$(PCAPLIB) $(LNETLIB) $(UNBOUNDLIB)



