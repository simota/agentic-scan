# ADR 0003: Catalogue prices are stored tax-exclusive

Status: accepted

Catalogue prices in `products.price` are stored **without** consumption tax.
Every surface adds tax when it shows or charges a price.
