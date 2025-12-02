#!/usr/bin/env python3
"""hcl2json - simple HCL (v2) to JSON converter

Reads HCL from a file or stdin and writes JSON to stdout or an output file.

Depends on: python-hcl2 (install via `pip install python-hcl2`)
"""
from __future__ import annotations

import argparse
import json
import sys
import os
from typing import Optional

try:
    import hcl2
except Exception as e:  # pragma: no cover - friendly import error
    print("Error: missing dependency 'python-hcl2'. Install with: python3 -m pip install python-hcl2", file=sys.stderr)
    raise


def parse_hcl_text(text: str):
    """
    Parse HCL (HashiCorp Configuration Language) text and return the equivalent Python data structure.

    This function attempts to use hcl2.loads(text) to parse an HCL string. On some hcl2 library
    versions the loads() function may not be available; in that case the function falls back to
    emulating loads() by wrapping the input text in a StringIO and calling hcl2.load(file_like).

    Parameters
    ----------
    text : str
        A string containing HCL source to be parsed.

    Returns
    -------
    object
        The Python representation of the parsed HCL content (typically a dict/list composed
        of native Python types: dict, list, str, int, float, bool, etc.), as returned by the
        underlying hcl2 library.

    Raises
    ------
    Exception
        Any exceptions raised by the underlying hcl2 implementation during parsing are propagated.
        This may include syntax/format errors or I/O related errors from the fallback path.
        An AttributeError is handled internally to detect the absence of hcl2.loads; it is not
        propagated.

    Notes
    -----
    - The function depends on the external hcl2 package being importable in the calling module.
    - Behavior may vary slightly depending on the hcl2 package version (hence the fallback).
    - The returned structure should be treated as read-only if you intend to regenerate HCL,
      since reserialization behavior depends on the specific library used.

    Examples
    --------
    >>> s = 'variable "image_id" { default = "ami-abc123" }'
    >>> parse_hcl_text(s)
    {'variable': {'image_id': {'default': 'ami-abc123'}}}
    """
    try:
        return hcl2.loads(text)
    except AttributeError:
        # Some versions provide load(s) only; if loads isn't available, emulate by using file-like
        from io import StringIO

        return hcl2.load(StringIO(text))


def parse_hcl_file(path: str):
    """
    Parse an HCL (HashiCorp Configuration Language) file and return the corresponding
    Python representation.

    This function opens the file at the given path using UTF-8 encoding and attempts to
    parse it using hcl2.load(). If the hcl2 implementation in the environment does not
    provide a load() function (raising AttributeError), the function falls back to
    reading the file contents and calling parse_hcl_text().

    Parameters
    ----------
    path : str
        Filesystem path to the HCL file to be parsed.

    Returns
    -------
    Any
        The Python object produced by the HCL parser (commonly a dict or list)
        representing the parsed HCL structure returned by hcl2.load or parse_hcl_text.

    Raises
    ------
    FileNotFoundError
        If the file at `path` does not exist.
    PermissionError
        If the file cannot be opened due to insufficient permissions.
    UnicodeDecodeError
        If the file cannot be decoded as UTF-8.
    Exception
        Any exceptions raised by the underlying HCL parser (hcl2.load or parse_hcl_text)
        other than AttributeError (which is handled internally to trigger the fallback).

    Notes
    -----
    - This function requires either the hcl2 module to expose a load(file-like) API or
      a local parse_hcl_text(text: str) helper that can parse HCL from a string.
    - The file is opened in text mode with UTF-8 encoding; very large files will be
      fully read into memory when the fallback path is used.
    - The exact return type depends on the HCL content and the parser implementation.

    Examples
    --------
    >>> parsed = parse_hcl_file("/etc/terraform/main.tf")
    >>> type(parsed)
    <class 'dict'>
    """
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return hcl2.load(fh)
        except AttributeError:
            # If load isn't available, fallback to loads
            return parse_hcl_text(fh.read())


def extract_aws_provider_version(parsed) -> Optional[str]:
    """Return the `version` string for the `aws` provider from a parsed HCL structure.

    This function is defensive and tolerant of several shapes that HCL parsers
    might produce. It searches the provided parsed structure for a Terraform
    `required_providers` declaration that references the `aws` provider and returns
    the associated `version` value.

    Search strategy and accepted shapes:
    - `parsed` may be a dict representing the whole file, or a list of top-level
        blocks (some parsers produce a list). If it's a list, each element is
        inspected in order.
    - A top-level Terraform block may be a dict or a list of dicts. The function
        normalizes either to a sequence of terraform blocks and inspects each.
    - The `required_providers` block may be:
        - a dict mapping provider names to provider metadata, e.g.
            {"aws": {"version": ">= 3.0.0"}}
        - a list of provider dicts, e.g. [{"aws": {"version": ">= 3.0.0"}}, ...]
    - The function returns the first `version` value found for the `aws` provider,
        in the order encountered while walking the top-level elements and terraform
        blocks. It does not validate the version string (semver, constraints, etc.).

    Args:
            parsed: The parsed HCL structure (typically a dict or list of dicts)
                    produced by an HCL/HCL2 parser. May be None or contain nested lists
                    and dicts.

    Returns:
            Optional[str]: The `version` value associated with the `aws` provider if
            found (commonly a string like ">= 3.0.0"); otherwise None.

    Examples:
            - parsed = {"terraform": {"required_providers": {"aws": {"version": ">= 3.0.0"}}}}
                -> ">= 3.0.0"
            - parsed = [{"terraform": {"required_providers": [{"aws": {"version": "~> 4.0"}}]}}]
                -> "~> 4.0"
            - parsed = None
                -> None

    Notes:
            - If multiple `aws` entries with `version` are present, the function returns
                the first one encountered during its traversal.
            - The function is intentionally permissive about input shapes to accommodate
                variations in different HCL parser outputs.

    Return the `version` for the `aws` provider from a parsed HCL structure.

    The parser may return a dict where keys map to lists/dicts. This function
    is defensive and will handle `terraform` being a list or dict, and
    `required_providers` being a dict or list.
    """

    if not parsed:
        return None

    if isinstance(parsed, list):
        # Rare, but handle top-level list by merging dicts
        # Search each element for terraform block
        elems = parsed
    elif isinstance(parsed, dict):
        elems = [parsed]
    else:
        return None

    for top in elems:
        if not isinstance(top, dict):
            continue

        terraform = top.get("terraform")
        if not terraform:
            continue

        terraform_blocks = terraform if isinstance(terraform, list) else [terraform]
        for tb in terraform_blocks:
            if not isinstance(tb, dict):
                continue

            rp = tb.get("required_providers")
            if not rp:
                continue

            # rp may be a dict mapping provider -> values, or a list of dicts
            if isinstance(rp, dict):
                aws_entry = rp.get("aws")
                if isinstance(aws_entry, dict) and "version" in aws_entry:
                    return aws_entry["version"]
            elif isinstance(rp, list):
                for item in rp:
                    if not isinstance(item, dict):
                        continue
                    aws_entry = item.get("aws")
                    if isinstance(aws_entry, dict) and "version" in aws_entry:
                        return aws_entry["version"]

    return None


def extract_terraform_info(parsed):
    """
    Extract terraform.required_version and required_providers information from a parsed HCL structure.

    This function walks one or more top-level parsed HCL objects and extracts:
    - the first-seen "required_version" value from any terraform block (returned as a string or None),
    - a mapping of provider names to a tuple (source, version).

    Arguments:
        parsed: Parsed HCL data. Expected forms:
            - None or falsy -> treated as empty (returns (None, {}))
            - dict -> a single top-level element
            - list -> a list of top-level elements (each typically a dict)
            Any other type is treated as empty.

    Behavior and handling details:
        - The function looks for top-level "terraform" blocks. Each terraform block may be
          a dict or a list of dicts.
        - required_version:
            - If one or more terraform blocks contain "required_version", the first non-empty
              value encountered is returned as the required_version (string). If none found,
              returns None.
        - required_providers:
            - The function supports multiple syntaxes for required_providers:
                - A dict mapping provider_name -> provider_spec
                - A list of dicts (each dict is merged by iterating items)
            - provider_spec can be:
                - a dict with keys "source" and/or "version"
                - a shorthand string which is treated as the version
            - For each provider name the function records a tuple (source, version),
              where missing source or version are returned as empty strings.
            - If a provider appears multiple times, the first-seen (source, version)
              pair is kept; subsequent occurrences are ignored.

    Return value:
        A tuple (required_version, providers_dict):
            - required_version: str or None
            - providers_dict: dict mapping provider_name (str) -> (source (str), version (str))

    Examples (conceptual):
        - parsed = {"terraform": {"required_version": ">= 1.0", "required_providers": {"aws": {"source": "hashicorp/aws", "version": "~> 4.0"}}}}
          -> (">= 1.0", {"aws": ("hashicorp/aws", "~> 4.0")})
        - parsed = [{"terraform": {"required_providers": [{"azurerm": ">=2.0"}]}}]
          -> (None, {"azurerm": ("", ">=2.0")})

    Notes:
        - The function is defensive: non-dict or unexpected shapes are skipped rather than raising.
        - The providers dict preserves only the first values seen for each provider name.

    Extract terraform.required_version and required_providers info.

    Returns (required_version, providers_dict) where providers_dict maps
    provider_name -> (source, version). Missing values are empty strings.
    """

    if not parsed:
        return None, {}

    if isinstance(parsed, list):
        elems = parsed
    elif isinstance(parsed, dict):
        elems = [parsed]
    else:
        return None, {}

    req_version = None
    providers: dict[str, tuple[str, str]] = {}

    for top in elems:
        if not isinstance(top, dict):
            continue

        terraform = top.get("terraform")
        if not terraform:
            continue

        terraform_blocks = terraform if isinstance(terraform, list) else [terraform]
        for tb in terraform_blocks:
            if not isinstance(tb, dict):
                continue

            # required_version may be present
            rv = tb.get("required_version")
            if rv and req_version is None:
                req_version = rv

            rp = tb.get("required_providers")
            if not rp:
                continue

            if isinstance(rp, dict):
                items = rp.items()
            elif isinstance(rp, list):
                # list of dicts
                items = []
                for item in rp:
                    if isinstance(item, dict):
                        items.extend(item.items())
            else:
                items = []

            for name, val in items:
                src = ""
                ver = ""
                if isinstance(val, dict):
                    src = val.get("source", "") or ""
                    ver = val.get("version", "") or ""
                elif isinstance(val, str):
                    # shorthand: version string
                    ver = val

                # keep first-seen values
                if name not in providers:
                    providers[name] = (src, ver)

    return req_version, providers


def _write_json(text: str, out_path: Optional[str] = None) -> None:
    """
    Docstring for _write_json

    :param text: Description
    :type text: str
    :param out_path: Description
    :type out_path: Optional[str]
    """
    if out_path:
        with open(out_path, "w", encoding="utf-8") as outfh:
            outfh.write(text)
    else:
        sys.stdout.write(text)


def _format_json(data, pretty: bool) -> str:
    """
    Docstring for _format_json

    :param data: Description
    :param pretty: Description
    :type pretty: bool
    :return: Description
    :rtype: str
    """
    if pretty:
        return json.dumps(data, ensure_ascii=False, indent=2)
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _print_aws_version_output(ver, rel_path: Optional[str], multiple: bool) -> None:
    """
    Docstring for _print_aws_version_output

    :param ver: Description
    :param rel_path: Description
    :type rel_path: Optional[str]
    :param multiple: Description
    :type multiple: bool
    """
    if multiple:
        print(f"{rel_path}: {ver}")
    else:
        # keep previous behavior of labeling single-file/stdout output
        print(f"Required AWS version: {ver}{'' if str(ver).endswith(chr(10)) else chr(10)}")


def _process_stdin(args) -> int:
    """
    Docstring for _process_stdin

    :param args: Description
    :return: Description
    :rtype: int
    """
    try:
        text = sys.stdin.read()
        if not text:
            print("Reading from stdin but nothing was provided. Provide HCL on stdin or use -i.", file=sys.stderr)
            return 2
        data = parse_hcl_text(text)
    except Exception as exc:
        print(f"Error: failed to parse HCL: {exc}", file=sys.stderr)
        return 4

    if args.aws_version:
        ver = extract_aws_provider_version(data)
        if ver is None:
            print("Error: aws provider version not found", file=sys.stderr)
            return 6
        _print_aws_version_output(ver, None, False)
        return 0

    if args.tf:
        req_version, providers = extract_terraform_info(data)
        if req_version is None and not providers:
            print("Error: terraform required_version/required_providers not found", file=sys.stderr)
            return 6
        parts = []
        if req_version:
            parts.append(str(req_version))
        for pname in sorted(providers.keys()):
            src, ver = providers[pname]
            parts.append(f"{pname}:{src}:{ver}")
        print(":".join(parts))
        return 0

    try:
        json_text = _format_json(data, args.pretty)
        _write_json(json_text, args.output)
    except Exception as exc:
        print(f"Error: failed to write JSON output: {exc}", file=sys.stderr)
        return 5

    return 0


def _process_files(args, input_files: list[str]) -> int:
    """
    Docstring for _process_files

    :param args: Description
    :param input_files: Description
    :type input_files: list[str]
    :return: Description
    :rtype: int
    """
    for idx, path in enumerate(input_files):
        try:
            data = parse_hcl_file(path)
        except FileNotFoundError as exc:
            print(f"Error: cannot open input file: {exc}", file=sys.stderr)
            continue
        except Exception as exc:
            print(f"Error: failed to parse HCL ({path}): {exc}", file=sys.stderr)
            continue

        # Print input file path relative to CWD; if it's deeply relative (more than 2 "../"), use absolute path
        try:
            rel_path = os.path.relpath(path, start=os.getcwd())
        except Exception:
            rel_path = path

        try:
            parts = rel_path.split(os.sep)
            leading_parents = 0
            for part in parts:
                if part == os.pardir:
                    leading_parents += 1
                else:
                    break
            if leading_parents > 2:
                rel_path = os.path.abspath(path)
        except Exception:
            # if anything goes wrong, keep rel_path as-is
            pass

        if args.aws_version:
            ver = extract_aws_provider_version(data)
            if ver is None:
                print(f"Error: aws provider version not found in {path}", file=sys.stderr)
                continue
            if len(input_files) > 1:
                print(f"{rel_path}: {ver}")
            else:
                _print_aws_version_output(ver, rel_path, False)
            continue

        if args.tf:
            req_version, providers = extract_terraform_info(data)
            if req_version is None and not providers:
                print(f"Error: terraform required_version/required_providers not found in {path}", file=sys.stderr)
                continue
            parts = []
            if req_version:
                parts.append(str(req_version))
            for pname in sorted(providers.keys()):
                src, ver = providers[pname]
                parts.append(f"{pname}:{src}:{ver}")
            line = ":".join(parts)
            if len(input_files) > 1:
                print(f"{rel_path}: {line}")
            else:
                print(line)
            continue

        try:
            json_text = _format_json(data, args.pretty)
            out_path = args.output if args.output else None
            # append newline when emitting multiple files to stdout
            suffix = "\n" if len(input_files) > 1 and out_path is None else ""
            _write_json(json_text + suffix, out_path)
        except Exception as exc:
            print(f"Error: failed to write JSON output for {path}: {exc}", file=sys.stderr)
            return 5

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert HCL (v2) to JSON")
    parser.add_argument("-i", "--input", help="Input HCL file path. If omitted reads from stdin.")
    parser.add_argument("-o", "--output", help="Output JSON file path. If omitted writes to stdout.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON with indentation")
    parser.add_argument("--aws-version", action="store_true", dest="aws_version",
                        help="Print only the terraform required_providers aws.version value and exit")
    parser.add_argument("--tf", "--terraform", action="store_true", dest="tf",
                        help="Print terraform required_version and required_providers source/version on one line and exit")

    args, extras = parser.parse_known_args(argv)

    # Determine input sources: leftover args are treated as input file paths
    if extras:
        input_files = extras
    elif args.input:
        input_files = [args.input]
    else:
        input_files = None

    # If multiple input files and a single output file was requested, avoid clobbering
    if input_files and args.output and len(input_files) > 1:
        print("Error: when providing multiple input files, do not specify a single -o/--output file", file=sys.stderr)
        return 7

    if input_files is None:
        return _process_stdin(args)

    return _process_files(args, input_files)


if __name__ == "__main__":
    raise SystemExit(main())

