+++
title = "The First Flag"
description = "Entry challenge!"
layout = "writeup"
category = "OSINT"
points = "50 pts"
time_spent = "5-10 mins"
tools_used = "Browser DevTools (Console, Elements, Application)"
date = "2026-10-15"
+++

The challenge asked you to read the [rules](https://tribectf.cs.wm.edu/rules/) page carefully. This year the flag was not in the page source. A Griffin waited in the browser console.

> The console game ran only during the event. It is no longer live on the rules page.

### Step 0: Find the Griffin

The rules page had an HTML comment near the top:

```html
<!-- The Griffin is listening. Open your console. -->
```

Open DevTools (F12) and go to the **Console** tab. The Griffin greets you:

```
Psst. The Griffin has your first flag. Type welcome()
```

Run `welcome()`, then introduce yourself with `iam("your name")`.

### Step 1: The hidden feather

The Griffin says a feather is hidden on the page, near "Eligibility". In the **Elements** tab, look under the *Eligibility/Team Formation* heading. You find a hidden element:

```html
<span id="griffin-feather" hidden data-word="wings"></span>
```

The word is in the `data-word` attribute, not the id. Submit it:

```js
answer("wings")
```

### Step 2: The gate

`door()` refuses you, because your `role` in `localStorage` is `guest`. Only griffins get in. Change the role and knock again:

```js
localStorage.setItem("role", "griffin")
door()
```

You can also edit the value in **Application > Local Storage**.

### Step 3: The riddle

The Griffin gives a base64 riddle. Decode it in the console:

```js
atob("SSBoYXZlIGtleXMgYnV0IG9wZW4gbm8gbG9ja3MuIEkgaGF2ZSBzcGFjZSBidXQgaG9sZCBubyByb29tLiBZb3UgY2FuIGVudGVyLCBidXQgbmV2ZXIgbGVhdmUuIFdoYXQgYW0gST8=")
// "I have keys but open no locks. I have space but hold no room.
//  You can enter, but never leave. What am I?"
answer("keyboard")
```

### Flag

The Griffin prints the flag:

```
tribectf{3v3ry_h4ck3r_5t4rt5_w17h_4_c0n50l3}
```

### Can you skip the game?

Partly. The answers are checked against SHA-256 hashes, so you cannot read them from the script. The flag is XOR-encrypted with the three answers joined (`wingsgriffinkeyboard`). The words are short and common, so a brute force works too. For 50 points, the game is the faster path.

**Bonus:** the console also answered to `caw()` and `fly()`.
