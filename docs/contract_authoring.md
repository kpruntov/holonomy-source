# Contract Authoring Guide

The Holonomy Structural & Logical Quality Linter requires a Data Contract defined in a strict JSON format. This document describes the schema expected by the `Validator`.

## What is a Data Contract?

A **Data Contract** defines the **structural and semantic shape** of a dataset. It is evaluated at write-time (during data ingestion) to ensure that incoming data meets specific quality constraints before it is written to storage.

Unlike a Policy (which governs *who* can access the data), a Contract governs *what* the data is. Crucially, the Contract is where **Semantic Tags** (e.g., `"pii"`, `"sensitive"`) are assigned to physical columns.

## The `DataContract` Object

The root object describes the dataset and its schema.

| Field | Type | Description |
|---|---|---|
| `name` | String | The name of the dataset (e.g., `EmployeeData`). |
| `version` | String | Semantic version of the contract. |
| `columns` | Array of `ColumnPolicy` | The array defining the exact structure and rules of the DataFrame. |

## The `ColumnPolicy` Object

Each column must be explicitly defined. If an incoming DataFrame has columns not defined here, it will be rejected as **Structural Drift**.

| Field | Type | Description |
|---|---|---|
| `name` | String | The exact column name. |
| `type` | String | A logical data type identifier (e.g., `string`, `int32`, `float64`). |
| `required` | Boolean | If `true`, the column must exist AND no null values are permitted in this column. |
| `regex` | String (Optional) | A regular expression that every string in this column must match. |
| `allowed_values` | Array of Strings (Optional) | A predefined list of categorical string values allowed for this column. |
| `range` | Object (Optional) | Numeric boundary checks. See `RangeRule`. |
| `tags` | Array of Strings (Optional) | Semantic tags assigned to this column (e.g., `["pii", "confidential"]`). These tags are used by the PolicyManifest to dynamically apply masking rules. |

## The `RangeRule` Object

Defines numeric bounds for any integer or floating-point type.

| Field | Type | Description |
|---|---|---|
| `min` | Float (Optional) | Minimum allowed value (inclusive). |
| `max` | Float (Optional) | Maximum allowed value (inclusive). |

## Example Contract (JSON)

```json
{
  "name": "EmployeeData",
  "version": "1.0",
  "columns": [
    {
      "name": "email",
      "type": "string",
      "required": true,
      "regex": "^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$",
      "tags": ["pii"]
    },
    {
      "name": "age",
      "type": "int32",
      "required": false,
      "range": { "min": 0, "max": 120 }
    },
    {
      "name": "salary",
      "type": "float64",
      "required": true,
      "range": { "min": 30000.0 },
      "tags": ["sensitive", "finance"]
    }
  ]
}
```

## Validation Errors (`Vec<LinterError>`)

When a batch is passed through `Validator::validate`, it returns an exhaustive list of all violations. Data Engineers will receive complete error vectors instead of single failures to accelerate debugging.

Errors include:

*   `MissingColumn`: A required column was not present in the dataset.
*   `ExtraColumn`: An undocumented column was found in the dataset.
*   `NullViolation`: A required column contained a null value.
*   `RegexViolation`: A string did not match the required regex pattern.
*   `RangeViolation`: A numeric value fell outside the allowed `min` or `max`.
*   `TypeMismatch`: The underlying Arrow physical type could not be validated against the rule.
