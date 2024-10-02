.PHONY: lint build publish clean docker

lint:
	pycodestyle . --ignore=E501

build:
	python3 -m build

publish: clean build
	twine upload dist/*

clean:
	rm -rf .pytest_cache dist s3tk.egg-info

docker: clean
	docker build --pull --no-cache --platform linux/amd64 -t ankane/s3tk:latest .
