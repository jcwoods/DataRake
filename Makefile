PROJECT=datarake

all:
	docker build -t $(PROJECT):latest .

.PHONY: test
test:
	python -m unittest discover -s tests -t .

.PHONY: golang
golang:
	$(MAKE) -C golang all

.PHONY: golang-test
golang-test:
	$(MAKE) -C golang test

.PHONY: clean
clean:
	rm -rf build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
