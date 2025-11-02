import os
import pyautogui

def next_filename(dir_path, base="screenshot", ext=".png"):
    """
    Return a non-overwriting filename inside dir_path.
    """
    i = 0
    while True:
        candidate = os.path.join(dir_path, f"{base}{ext}" if i == 0 else f"{base}_{i}{ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1

def take_screenshot(save_dir=r"C:\Users\pro\Documents\pythoncodepics", base_name="screenshot"):
    """
    Capture a screenshot and save it into save_dir with a non-overwriting filename.
    """
    os.makedirs(save_dir, exist_ok=True)

    screenshot = pyautogui.screenshot()

    save_path = next_filename(save_dir, base=base_name, ext=".png")
    screenshot.save(save_path)

    print(f"Saved screenshot to: {save_path}")
    return save_path

if __name__ == "__main__":
    take_screenshot()
