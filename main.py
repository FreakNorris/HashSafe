import tkinter as tk
from ui_handler import UIHandler
from functional_handler import FunctionalHandler

def main():
    root = tk.Tk()
    root.title("HashSafe")
    
    # Initialize FunctionalHandler with None for ui_handler temporarily
    functional_handler = FunctionalHandler(None)
    
    # Initialize UIHandler with the root and functional_handler
    ui_handler = UIHandler(root, functional_handler)
    
    # Assign the ui_handler to functional_handler
    functional_handler.ui_handler = ui_handler
    
    root.mainloop()

if __name__ == "__main__":
    main()