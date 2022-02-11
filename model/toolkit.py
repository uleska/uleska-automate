from dataclasses import dataclass


@dataclass
class Toolkit(dict):
    def __init__(self, id, name, description, uleskaApproved, customerId):
        super().__init__(self)
        self["id"] = id
        self["name"] = name
        self["description"] = description
        self["uleska_approved"] = uleskaApproved
        self["customer_id"] = customerId
