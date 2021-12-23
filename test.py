shared_list = "123@gmail.com 456@gmail.com 789@gmail.com"
user = "123@gmail.com"
if user not in shared_list:
    print("This user has no access")
else:
    print("This user has been shared")
