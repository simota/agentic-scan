# Reporting: chat summary and checklist

**Read when:** REPORT; or when only a checklist was asked for.

## Chat summary

First line: status and counts, taken from `findings.py counts`. Then, in order:

1. Open defects by severity, and the IDs to read first
2. The pattern that recurs most, with its `Traced` count and the base rate where it matters. Do not write
   "root cause" for a `Blamed` origin
3. How much was read (`meta.sample`) and what the history could not show. Say plainly what was not run, and
   do not write a total when the run read a sample
4. One line per decision a person must make
5. The output directory and the scratch path

## Checklist (when only that was asked)

- Core flows
- Gates found, absent and unknown
- Patterns likely here, with the reason from the stack or history
- Surfaces worth tracing first
- What the history can and cannot support

No output files; put a long list in `<scratch>/checklist.md` and name it.
