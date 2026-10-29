.PHONY: lint build publish clean docker docker-release

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

docker-release:
	docker buildx build --push --pull --no-cache --platform linux/amd64,linux/arm64 -t ankane/s3tk:latest -t ankane/s3tk:v0.5.1 .
