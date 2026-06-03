PROJECT=datarake

all:
	docker build -t $(PROJECT):latest .

.PHONY: test
test:
	python -m unittest discover -s tests -t .
