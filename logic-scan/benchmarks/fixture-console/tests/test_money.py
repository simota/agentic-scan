import unittest

from console.money import tax_on, with_tax


class MoneyTests(unittest.TestCase):
    def test_tax_rounds_down(self):
        self.assertEqual(tax_on(333), 33)

    def test_with_tax(self):
        self.assertEqual(with_tax(1000), 1100)


if __name__ == "__main__":
    unittest.main()
