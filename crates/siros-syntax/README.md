# siros-syntax

Values in their literal forms, and the lists that hold values.

[`Count`], [`Decimal`], [`Currency`], [`Amount`], [`Date`], [`Time`], [`Offset`],
[`OffsetTime`] and [`DateTime`] each write their literal with `Display` (`1234.5`, `EUR`,
`42.50 EUR`, `2026-09-02`, `12:30:15.5+02:00`), and `parse` accepts exactly what `Display`
writes: a value is its literal. A text outside the form is [`Malformed`], with the byte where it
leaves the form. [`Keyed`] holds values under distinct keys, [`AllOf`] one or more values, and
[`checked!`] makes a value of a type whose rule a `const fn` holds when the crate builds.

```rust
use siros_syntax::{Amount, Date, Malformed};

let amount = Amount::parse("42.50 EUR")?;
assert_eq!((amount.value().units(), amount.value().scale()), (4250, 2));
assert_eq!(amount.to_string(), "42.50 EUR");
assert_eq!(Date::parse("2026-02-29"), Err(Malformed { of: "Date", at: 8 }));
# Ok::<(), Malformed>(())
```

## Currencies

[`Currency`] takes the alphabetic codes of ISO 4217 List One, the table of current currencies and funds.
`list-one.xml` is the file SIX publishes for the ISO 4217 Maintenance Agency, published
2026-09-17 (its `Pblshd` attribute), SHA-256
`33139b438657d1cee116ba737807ea71d19d6de4b90f799a09c56f0cc6a1b0ff`. The build script reads each
listed code with its minor units; an entry outside List One's form fails the build. A code List
One does not list is [`Malformed`].

To take a new edition, replace `list-one.xml` with the file at
<https://www.six-group.com/dam/download/financial-information/data-center/iso-currrency/lists/list-one.xml>
and update the date and hash above.
