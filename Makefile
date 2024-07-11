CC = gcc
LIBNAME = capstone

capstone_dis: capstone_dis.o
	${CC} $< -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
