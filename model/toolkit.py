from dataclasses import dataclass


@dataclass
class Toolkit(dict):
    def __init__(self, id, name, description, uleska_approved, customer_id):
        super().__init__(self)
        self["id"] = id
        self["name"] = name
        self["description"] = description
        self["uleska_approved"] = uleska_approved
        self["customer_id"] = customer_id
