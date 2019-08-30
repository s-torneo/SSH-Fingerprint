#
# SSH-Fingerprint Progetto del corso di Gestione Rete 2018/2019 
# 
# Dipartimento di Informatica Università di Pisa
# Docente: Luca Deri
#
#

CC		=  gcc
CFLAGS	        += -std=c99 -Wall
LIBS            = -lpcap

SOURCE = filter_new.c

OBJECTS	= filter_new.o

TARGETS = filter_new

.PHONY: clean test1

$(TARGETS): $(SOURCE)
	$(CC) $(SOURCE) -o $(TARGETS) $(LIBS)

clean : 
	rm -f $(TARGETS)
	rm -f $(OBJECTS)

test1 :
	make clean
	make
	./filter ssh_sample.pcapng
