test:
	py.test tests

install:
	pip install -r requirements.txt

publish:
	rm -fr build dist s3tk.egg-info
	python setup.py bdist_wheel --universal
	ls dist
	# twine upload dist/*
	rm -fr build dist s3tk.egg-info
