# Merchant console — business rules

The console bills merchants for a subscription and shows them their sales.
Amounts are integer minor units (yen) unless a section says otherwise. The
business day is Japan time (Asia/Tokyo).

## Orders and states

1. Order states are defined in `console/states.py`. A merchant's **sales** are
   orders that are `paid`, `shipped`, `delivered` or `partially_refunded`.
2. The order quantity per line is 1 to 100 inclusive, on every surface (API and
   web form).
3. The dashboard's average order value is total sales divided by the number of
   sales orders; a merchant with no sales sees 0.

## Reporting periods

4. A monthly report covers every order created from the first day of the month
   00:00 up to, but not including, the first day of the next month, in Japan time.
5. The exchange rate used for a report is the **most recent** rate published
   for the currency.
6. Revenue per merchant is the sum of order amounts. Each order may have several
   payments (split payments); payments never change the order amount.

## Plans and discounts

7. Plans: `free`, `standard`, `pro`. An unknown plan code is an error.
8. Merchants on tier 2 or above get the partner discount of 10%. Tiers come from
   `config/tiers.json`.
9. The partner discount applies to the **pre-tax** amount; tax (10%) is then
   computed on the discounted amount and rounded down.
10. Suspended merchants never get free shipping. Otherwise free shipping applies
    to members, or to any order of 5,000 yen or more.

## Imports and messages

11. The supplier price CSV uses European number format: `1.234,56` means one
    thousand two hundred thirty-four point five six.
12. SMS bodies are limited to 70 **characters** (Japanese text counts one per
    character).

## Surveys

13. A survey answer is `true`, `false`, or not answered (`null`). Reports count
    the three separately.

## Settlement

14. A settlement batch is marked done only when every payout in it succeeded.

## Promotions

15. A promotion period is a single day when its start date and end date are the
    same calendar date.
