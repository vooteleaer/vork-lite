"""Reads the board's log (COM port, 115200) for N seconds into a file; resets it first with --reset."""
import re, sys, time
import serial

port, secs, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
s = serial.Serial(port, 115200, timeout=1)
if "--reset" in sys.argv:
    s.setDTR(False); s.setRTS(True); time.sleep(0.1); s.setRTS(False)
end = time.time() + secs
with open(out, "w", encoding="utf-8") as f:
    while time.time() < end:
        line = s.readline()
        if line:
            f.write(re.sub(r"\x1b\[[0-9;]*m", "", line.decode("utf-8", "replace").rstrip()) + "\n")
            f.flush()
