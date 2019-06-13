#
# SSH-Fingerprint Progetto del corso di Gestione Rete 2018/2019 
# 
# Dipartimento di Informatica Università di Pisa
# Docenti: Luca Deri
#
#

CC		=  gcc
CFLAGS	        += -std=c99 -Wall
LIBS            = -lpcap

SOURCE = filter.c

OBJECTS		= filter.o

TARGETS = filter

.PHONY: clean test1

$(TARGETS): $(SOURCE)
	$(CC) $(SOURCE) -o $(TARGETS) $(LIBS)

clean		: 
	rm -f $(TARGETS)
	rm -f $(OBJECTS)

test1 :
	make clean
	make
	sudo ./filter ssh_sample.pcapng
