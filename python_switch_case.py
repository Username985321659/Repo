#option 1 - match

def switch_case2(x):
    match x:
        case 1:
            return "One"
        case 2:
            return "Two"
        case 3:
            return "Three"
        case _:
            return "Other"

# Example usage:
print(switch_case2(2))  # Output: Two

#option 2 - dictionary

def case_one():
    return "One"

def case_two():
    return "Two"

def case_three():
    return "Three"

def default_case():
    return "Other"

def switch_case(x):
    switch_dict = {
        1: case_one,
        2: case_two,
        3: case_three
    }
    return switch_dict.get(x, default_case)()

# Example usage:
print(switch_case(2))  # Output: Two



