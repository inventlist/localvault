---
title: "Scoped Env Injection: AWS Without Hand-Rolled Exports"
description: "LocalVault env and exec now support selectors, exclusions, explicit mappings, and an AWS profile so subprocesses receive only the secrets they need."
type: doc
---

# Scoped Env Injection: AWS Without Hand-Rolled Exports

Dot-notation is good for organizing a vault:

```bash
AWS_IAM.access_key_id
AWS_IAM.secret_access_key
AWS_SES.smtp_password
AWS_S3.bucket
```

But shell tools do not know LocalVault namespaces. By default, a nested key like
`AWS_IAM.access_key_id` becomes:

```bash
AWS_IAM__access_key_id
```

That is readable, but the AWS CLI expects:

```bash
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
```

LocalVault now gives `env` and `exec` the same projection DSL, so you can scope
and map values at the boundary where they enter a process.

## Use the AWS Profile

For AWS commands, use the built-in profile:

```bash
localvault exec --profile aws -- aws sts get-caller-identity
```

The profile does two things:

1. Scopes injection to `AWS_IAM.*`
2. Maps LocalVault names to standard AWS environment variables

The built-in mappings are:

| LocalVault key | Environment variable |
|---|---|
| `AWS_IAM.access_key_id` | `AWS_ACCESS_KEY_ID` |
| `AWS_IAM.secret_access_key` | `AWS_SECRET_ACCESS_KEY` |
| `AWS_IAM.session_token` | `AWS_SESSION_TOKEN` |

If `AWS_IAM.session_token` is not present, nothing extra is injected.

## Select Only What a Process Needs

Selectors are intentionally small:

| Selector | Meaning |
|---|---|
| `KEY` | exact key |
| `GROUP.*` | all keys in a dot namespace |
| `A,B,C` | multiple selectors |

Examples:

```bash
localvault exec --only AWS_IAM.* -- aws sts get-caller-identity

localvault exec --only AWS_IAM.*,AWS_SES.* -- your-script

localvault env --only OPENAI_API_KEY,AWS_IAM.*
```

This is least-privilege injection. A subprocess that only needs AWS identity
does not also receive Stripe, database, or webhook secrets from the same vault.

## Exclude After Selecting

Use `--except` to remove a narrower set after selecting a broader namespace:

```bash
localvault exec \
  --only AWS_IAM.*,AWS_SES.* \
  --except AWS_SES.smtp_password \
  -- your-script
```

The process receives AWS identity values and the rest of the SES namespace, but
not the SMTP password.

## Map One Key Explicitly

Use `--map` when a tool expects a specific variable name:

```bash
localvault exec \
  --only AWS_IAM.access_key_id \
  --map AWS_IAM.access_key_id=AWS_ACCESS_KEY_ID \
  -- your-command
```

The same mapping works with `env`:

```bash
localvault env --map AWS_IAM.access_key_id=AWS_ACCESS_KEY_ID
```

`env` prints export lines for shell sourcing. `exec` is safer for most work
because values go straight into the child process environment.

## Override A Profile

Profiles are defaults, not a cage. Explicit maps win:

```bash
localvault exec \
  --profile aws \
  --map AWS_IAM.access_key_id=CUSTOM_AWS_KEY \
  -- your-command
```

Projection order is:

1. Apply profile maps
2. Apply `--only`
3. Apply `--except`
4. Apply explicit `--map`

That gives LocalVault useful defaults while still letting you adapt to odd
tools.

## Dot to Double Underscore

When no mapping is provided, nested keys still use the long-standing transform:

```bash
GROUP.key
# becomes
GROUP__key
```

The group is uppercased, the subkey is kept as written. That keeps all-project
injection collision-safe:

```bash
platepose.DATABASE_URL
inventlist.DATABASE_URL

# become
PLATEPOSE__DATABASE_URL
INVENTLIST__DATABASE_URL
```

Use `-p PROJECT` when you want one project group without the prefix:

```bash
localvault exec -p platepose -- rails server
```

Use the selector DSL when you want cross-project or service-specific injection.

## A Practical Pattern

For day-to-day cloud work:

```bash
localvault exec --profile aws -- aws sts get-caller-identity
localvault exec --profile aws -- aws s3 ls
localvault exec --only AWS_IAM.*,AWS_SES.* -- your-mailer-check
```

The vault can hold everything. The process only gets what it needs.
