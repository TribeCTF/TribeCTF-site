+++
title = "Registeel"
description = "Help! Registeel is rusting! Can you help us?"
layout = "writeup"
category = "Cage"
points = "300 pts"
time_spent = "5 mins"
tools_used = "Text editor, base64 (or CyberChef)"
date = "2026-10-15"
+++

The file `sealed_chamber.bin` is plain text, not binary. Open it in any text editor.

### Step 1: Find the base64 string

Most of the file is noise. Look for a string made only of letters, digits, `+` and `/`, sometimes with one or two `=` at the end. The maintenance log has one:

```
maintenance access token:
  dHJpYmVjdGZ7dU5yVTVUMU5HX1IzZzFTdGUzbH0=
```

### Step 2: Decode it

```
$ echo 'dHJpYmVjdGZ7dU5yVTVUMU5HX1IzZzFTdGUzbH0=' | base64 -d
tribectf{uNrU5T1NG_R3g1Ste3l}
```

CyberChef's **From Base64** works too.

### Flag

```
tribectf{uNrU5T1NG_R3g1Ste3l}
```

The rest of the file, including the `SEED` and `CORE_ALLOY` values, is a distraction.
