import time
import random
import os
import mss

# מילים שיגרמו לצילום מסך
TRIGGER_WORDS = ["password", "username", "login", "secret", "admin", "123456"]

#  תיקיות לשמירה וליצר אותם
LOG_FOLDER = "logs"
SCREENSHOT_FOLDER = "screenshots"

# פונקציה לצילום מסך
def take_screenshot():
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    filename = f"{SCREENSHOT_FOLDER}/triggered_screenshot_{timestamp}.png"
    with mss.mss() as sct:
        sct.shot(output=filename)
    print(f" Screenshot saved: {filename}")

# פונקציה לסימולציית הקלדה
def simulate_input_capture(duration=20):
    keys = [
        "hello", "user", "password", "test", "login", "data", "admin",
         "email", "name", "info", "guest", 
    ]
    log_file = f"{LOG_FOLDER}/input_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    start_time = time.time()

    with open(log_file, "w") as f:
        while time.time() - start_time < duration:
            key = random.choice(keys)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            log_line = f"[{timestamp}] Key pressed: {key}\n"
            f.write(log_line)
            print(log_line.strip())

            # בדיקת טריגר
            if key.lower() in TRIGGER_WORDS:
                print(f" Trigger word detected: {key} — taking screenshot...")
                take_screenshot()

            time.sleep(random.uniform(0.5, 1.2))

    print(f"\n Input log saved to {log_file}")

# פונקציה ראשית
def main():
    print(" Starting Malware Simulation...\n")
    simulate_input_capture()
    print("\n Simulation complete. Logs and screenshots saved.")

if __name__ == "__main__":
    main()

