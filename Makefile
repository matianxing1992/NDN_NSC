TARGETS = consumer producer delay_producer
CFLAGS = `pkg-config --cflags --libs libndn-cxx`

all: $(TARGETS)

consumer: consumer.cpp
	g++ -std=c++17 $< -o $@ -Wall -ggdb -O0 $(CFLAGS)

producer: producer.cpp
	g++ -std=c++17 $< -o $@ -Wall -ggdb -O0 $(CFLAGS)

delay_producer: producer_with_delay.cpp
	g++ -std=c++17 $< -o $@ -Wall -ggdb -O0 $(CFLAGS)

clean:
	rm -rf *.dSYM
	rm -rf $(TARGETS)
