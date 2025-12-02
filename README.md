[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat" )](http://choosealicense.com/licenses/mit/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?style=flat-square&logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)



# utils
Various utilities

<details>

<summary>hcl2json.py</summary>

## hcl2json.py
A python script to parse HCL and convert to JSON.
Can also report just the terraform {} block, showing `required_verssion` and `required_proveders` source and version info, on 1 line per file, separated by ':'

#### Requires
- [python-hcl2](https://pypi.org/project/python-hcl2/)


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

With zsh:
```
setopt extended_glob
python3 hcl2json.py --tf **/terraform.tf
```
This will report the `terraform` settings for all `terraform.tf` files recursivly

</details>
