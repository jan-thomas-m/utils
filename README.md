# utils
Various utilities

## hcl2json.py

```
usage: hcl2json.py [-h] [-i INPUT] [-o OUTPUT] [--pretty] [--aws-version] [--tf]

Convert HCL (v2) to JSON

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input HCL file path. If omitted reads from stdin.
  -o OUTPUT, --output OUTPUT
                        Output JSON file path. If omitted writes to stdout.
  --pretty              Pretty-print JSON with indentation
  --aws-version         Print only the terraform required_providers aws.version value and exit
  --tf, --terraform     Print terraform required_version and required_providers source/version on one line and exit

```
