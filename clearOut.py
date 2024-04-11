import os

# Clears output folder by removing each file in directory
def clearOut():
    for o in os.listdir("./output/"):
        print(f"x Removing [ {o} ]...    ", end="")
        os.remove(f"./output/{o}")
        print("✓ Removed")

clearOut()