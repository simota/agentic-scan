from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    code: str
    monthly_fee: int


PLANS = [Plan("free", 0), Plan("standard", 3000), Plan("pro", 9800)]


def plan_for(code):
    return next((plan for plan in PLANS if plan.code == code), PLANS[0])
