lint:
	pycodestyle . --ignore=E501

publish: clean
	python3 -m build
	ls dist
	twine upload dist/*
	make clean

clean:
	rm -rf .pytest_cache build dist s3tk.egg-info

docker:
	docker build --pull --no-cache --platform linux/amd64 -t ankane/s3tk:latest .
