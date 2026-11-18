# Shop business rules

These rules are the specification the code must follow. Amounts are Japanese
yen, stored as integers. The business runs on Japan time (Asia/Tokyo).

## Prices and tax

1. Consumption tax is 10%. Tax is computed **per line** and rounded **down**
   to the yen. The invoice total and the amount charged to the card must be
   the same number.
2. Bulk discount: a line with a quantity of **10 or more** gets 5% off its
   net amount, rounded down.
3. A quantity must be at least 1.

## Shipping

4. Shipping is free when the order's net amount (after discounts, before tax)
   is **5,000 yen or more**. Otherwise the standard fee is 600 yen.
5. A shipping fee set on the order by staff overrides the standard fee. Staff
   set it to 0 to ship an order for free.
6. Remote regions add a surcharge from the surcharge table. A region not in the
   table has no surcharge.

## Promotions and coupons

7. A promotion is active from its start (inclusive) to its end (exclusive):
   a promotion ending at 2026-12-01 00:00 is not active at that instant.
8. A coupon can be used once per user.

## Points

9. Members earn points equal to `point_rate_percent` percent of the net amount,
   rounded down. The default rate is 1%.

## Orders

10. Order states: `pending` → `paid` → `shipped` → `delivered`. An order can be
    cancelled only while `pending` or `paid`.
11. Same-day shipping applies to orders paid before 14:00 Japan time.
12. The shipping address is the customer's most recently added address.

## Subscriptions

13. A monthly subscription renews on the same day of the next calendar month
    (clamped to the month's last day).

## Accounts

14. Email addresses are unique regardless of letter case and surrounding spaces.
