# Patrowl4py
Python API Client for PatrowlManager, PatrowlEngines and PAtrowlArsenal

# Pypi Deployment commands
```
rm -rf dist/ build/ PatrowlEnginesUtils.egg-info
python setup.py sdist bdist_wheel
twine upload dist/*
```
