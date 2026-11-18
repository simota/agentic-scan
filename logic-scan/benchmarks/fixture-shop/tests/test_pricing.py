import unittest

from shop.pricing import line_net, line_tax


class PricingTests(unittest.TestCase):
    def test_line_tax_rounds_down(self):
        self.assertEqual(line_tax(333), 33)

    def test_small_line_has_no_discount(self):
        self.assertEqual(line_net(100, 2), 200)


if __name__ == "__main__":
    unittest.main()
