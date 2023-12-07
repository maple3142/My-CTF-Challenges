#!/usr/bin/env python3
from picklescan.scanner import scan_pickle_bytes, SafetyLevel
import io, pickle, base64

inp = input("Base64 encoded pickle: ")
pkl = base64.b64decode(inp)
result = scan_pickle_bytes(io.BytesIO(pkl), 1337)
if (
    result.scan_err
    or result.issues_count > 0
    or not all([g.safety == SafetyLevel.Innocuous for g in result.globals])
):
    print("Dangerous pickle!")
    exit()

pickle.loads(pkl)
