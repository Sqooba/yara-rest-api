YARA Rest API
====

This is a simple REST API to apply pre-loaded Yara rules on a file POST'ed
to the REST API endpoint.

# Build it
```
docker build -t yara-rest-api .
```

# Get sample yara rules
-> https://valhalla.nextron-systems.com/ 
Check "DEMO", get the rules.
Save the file in `rules` folder

# Run it

```
docker run -it -v ${PWD}/rules:/rules -e YARA_RULES_DIR=/rules -p 8080:8080 yara-rest-api
```

# Submit a sample

Assuming you have a file `sample.bin`, run the following command:
```
curl http://localhost:8080/yara -F "sample=@sample.bin" -vvv
```

Expected output:

```
{"matchingRules": ["ns1/testns1"]}
```
