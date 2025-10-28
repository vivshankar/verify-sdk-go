#!/usr/bin/env python3
from typing import Any


import json
import sys
from pathlib import Path

def transform(doc):
    # 1) Rename BasicAuth → api_key
    for sec in doc.get("security", []):
        if "BasicAuth" in sec:
            sec["api_key"] = sec.pop("BasicAuth")

    # 2) Strip trailing slash on paths\
    paths = doc.get("paths", {})
    new_paths = {}
    for p, spec in paths.items():
        if p != "/" and p.endswith("/"):
            p = p[:-1]
        new_paths[p] = spec
        
    # 3) Within each operation, clean up parameter schemas
        for operation in spec.values():
            params = operation.get("parameters", [])
            for param in params:
                schema = param.get("schema")
                if not isinstance(schema, dict):
                    continue

                # 3a) Flatten nested arrays-of-arrays
                if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
                    items = schema["items"]
                    if items.get("type") == "array" and "items" in items and "enum" in items:
                        # take the inner items definition and carry over the enum
                        inner = items["items"]
                        new_items = dict(inner)            
                        new_items["enum"] = items["enum"]  
                        schema["items"] = new_items        # replace array-of-array with simple array
                        schema.pop("enum", None)           
                        items = new_items

                # 3b) Drop boolean schema enums
                if schema.get("type") == "boolean" and "enum" in schema:
                    del schema["enum"]

                # 3c) Drop redundant array schema enums
                if (
                    schema.get("type") == "array"
                    and "enum" in schema
                    and isinstance(schema.get("items"), dict)
                    and "enum" in schema["items"]
                ):
                    del schema["enum"]

    doc["paths"] = new_paths

    # 4) change ref to eliminate duplicates
    ref_map = {
        "#/components/schemas/Attribute1": "#/components/schemas/Attribute",
        "#/components/schemas/ErrorBean1": "#/components/schemas/ErrorBean",
        "#/components/schemas/OperationAndValue_0": "#/components/schemas/OperationAndValue",
        "OperationAndValue\"": "DynamicGroupCondition\"",
        "\"RequestOperation\":": "\"AccessRequestOperation\":",
        "/RequestOperation": "/AccessRequestOperation",
        "\"/\": {": "\"/\": {\"x-go-name\": \"URLPathRegex\",",
        "\"?\": {": "\"?\": {\"x-go-name\": \"URLQueryRegex\",",
        "\"#\": {": "\"#\": {\"x-go-name\": \"URLFragmentRegex\",",
        "\"Client\":": "\"AuthenticatorClient\":",
        "\"#/components/schemas/Client\"": "\"#/components/schemas/AuthenticatorClient\"",
        "\"type\": \"string\"": "\"type\": \"string\",\"x-go-type-skip-optional-pointer\": true",
        "\"type\": \"boolean\"": "\"type\": \"boolean\",\"x-go-type-skip-optional-pointer\": true",
        "\"type\": \"integer\"": "\"type\": \"integer\",\"x-go-type-skip-optional-pointer\": true",
    }

    text = json.dumps(doc)
    for key, value in ref_map.items():
        print(f"Replacing {key} => {value}")
        text = text.replace(key, value)

    doc = json.loads(text)    

    # 5) delete specific objects
    del doc["components"]["schemas"]["HttpServletRequest"]
    del doc["components"]["schemas"]["AsyncContext"]
    del doc["components"]["schemas"]["ServletRequest"]
    del doc["components"]["schemas"]["ServletResponse"]
    del doc["components"]["schemas"]["ClassLoader"]
    del doc["components"]["schemas"]["ServletContext"]
    del doc["components"]["schemas"]["HttpSession"]
    del doc["components"]["schemas"]["ServletConfig"]
    
    # 6) Fix the attributes API response
    doc["paths"]["/v1.0/attributes"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "anyOf": [
            {
                "type": "array",
                "items": {
                    "$ref": "#/components/schemas/Attribute_0"
                }
            },
            {
                "$ref": "#/components/schemas/PaginatedAttribute_0"
            }
        ]
    }

    doc["components"]["schemas"]["PaginatedAttribute_0"] = {
                "required": [
                    "limit",
                    "page",
                    "total",
                    "count",
                    "attributes"
                ],
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer"
                    },
                    "page": {
                        "type": "integer"
                    },
                    "total": {
                        "type": "integer"
                    },
                    "count": {
                        "type": "integer"
                    },
                    "attributes": {
                        "type": "array",
                        "description": "list of attributes",
                        "items": {
                            "$ref": "#/components/schemas/Attribute_0"
                        }
                    }
                }
            }

    # 7) Fix the identity sources API
    doc["paths"]["/v2.0/identitysources"]["get"]["parameters"].append({
                        "name": "count",
                        "in": "query",
                        "description": "The prefix for the count parameter is <b>count=</b>. ",
                        "schema": {
                            "type": "integer",
                            "x-go-type-skip-optional-pointer": True
                        }
                    })

    doc["components"]["schemas"]["IdentitySourceInstancesData"]["properties"]["id"] = {
                        "type": "string",
                        "description": "The ID of the identity source",
                        "example": "00000000-1111-2222-3333-444444444444"
                    }

    # 8) Fix the  CD objects
    del doc["components"]["schemas"]["PatchOperation_0"]["properties"]["value"]["type"] # make this object type

    # 9) Fix API clients
    doc["paths"]["/v1.0/apiclients"]["get"]["responses"]["200"]["content"]["application/json"] = {
                                "schema": {
                                    "$ref": "#/components/schemas/APIClientConfigPaginatedResponseContainer"
                                }
                            }
    doc["components"]["schemas"]["APIClientConfig"]["properties"]["additionalProperties"] = {
                        "type": "object",
                        "description": "additional properties for the client"
                    }

    # 10) Fix applications
    doc["components"]["schemas"]["AdminApplicationWithoutProv"]["properties"]["applicationState"]["x-go-type"] = "StringOrBoolean"
    doc["components"]["schemas"]["AdminApplicationWithoutProv"]["properties"]["approvalRequired"]["x-go-type"] = "StringOrBoolean"
    doc["components"]["schemas"]["AdminApplicationWithoutProv"]["properties"]["visibleOnLaunchpad"]["x-go-type"] = "StringOrBoolean"
    doc["components"]["schemas"]["OIDCPropertiesBean"]["properties"]["additionalConfig"]["$ref"] = "#/components/schemas/AdditionalConfiguration"

    return doc


def main(infile, outfile):
    data = json.loads(Path(infile).read_text())
    fixed = transform(data)
    # ensure_ascii=False to keep the unicode
    Path(outfile).write_text(json.dumps(fixed, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {outfile}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.json output.json")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])