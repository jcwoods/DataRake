PROJECT=datarake

all:
	docker build -t $(PROJECT):latest .
