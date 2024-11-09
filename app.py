import subprocess

def execute_file(file_path):
    """Execute a Python file given its path."""
    subprocess.run(["python", file_path])

# Main loop
while True:
    print("\nChoose an option:")
    print("1. Static Analysies ")
    print("2. Dynamic Analysies ")
    print("3. Execute option 3")
    print("4. Exit")
    
    try:
        choice = int(input("Enter your choice: "))
        
        if choice == 1:
            execute_file("/home/kali/Downloads/MAT/src/static.py")
        elif choice == 2:
            execute_file("/home/kali/Downloads/MAT/src/dynamic.py")
        elif choice == 3:
            execute_file("option3.py")
        elif choice == 4:
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")
    except ValueError:
        print("Please enter a valid number.")
