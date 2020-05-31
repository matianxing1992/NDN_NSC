TARGETS = consumer producer
CFLAGS = `pkg-config --cflags --libs libndn-cxx`

all: $(TARGETS)

consumer: consumer.cpp
	g++ -std=c++14 $< -o $@ -Wall -ggdb -O0 $(CFLAGS)

producer: producer.cpp
	g++ -std=c++14 $< -o $@ -Wall -ggdb -O0 $(CFLAGS)

clean:
	rm -rf *.dSYM
	rm -rf $(TARGETS)
