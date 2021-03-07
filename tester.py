



def check_common(check_input):
    """Check Common function"""
    flag = 0
    with open("CommonPassword.txt") as c_p:
        for line in c_p:
            if check_input == line.strip():
                flag = line.strip()
    return flag

def something():
    password = input("enter a password")
    lower = password.lower()
    notgood = False
    while not notgood:
        if check_common(lower) == lower:
            notgood = False
            print("The secret", password, "is too common to use, "
                                           "try again with something else.")
            password = input("enter a password")
        else:
            print("Your secret is strong!")
            print(lower)
            notgood = True


something()

