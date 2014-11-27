CC = rustc
FILES = src/lib.rs
TARGET = ./libkeepass.rlib
TEST_TARGET = ./keepass

all:
	$(CC) --crate-type=lib $(FILES)

test:
	$(CC) --crate-type=lib --test $(FILES)
	$(TEST_TARGET)

clean:
	rm -f $(TARGET)
	rm -f $(TEST_TARGET)

.PHONY: all test clean
